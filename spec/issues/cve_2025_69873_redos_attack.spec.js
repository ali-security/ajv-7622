'use strict';

var Ajv = require('../ajv');
require('../chai').should();

/*
 * Port of the upstream v8 ReDoS test suite for CVE-2025-69873:
 *   https://github.com/ajv-validator/ajv/commit/720a23fa453ffae8340e92c9b0fe886c54cfe0d5
 *
 * Adapted to ajv v6 (CommonJS, no TypeScript). The new `code.regExp` option in
 * lib/dot/pattern.jst + lib/compile/index.js mirrors the upstream API so users
 * can plug in a linear-time regex engine (re2) and obtain real ReDoS
 * protection against attacker-controlled $data patterns.
 *
 * The native JavaScript RegExp is NOT ReDoS-safe -- catastrophic backtracking
 * does not throw, so try/catch alone cannot mitigate it. Tests that exercise
 * actual ReDoS resistance therefore require the `re2` package to be installed
 * (it is an optional native dep) and are skipped otherwise.
 */
var re2;
try { re2 = require('re2'); } catch (e) { /* optional native dep */ }
var itRe2 = re2 ? it : it.skip;

var SCHEMA = {
  type: 'object',
  properties: {
    pattern: {type: 'string'},
    value: {type: 'string', pattern: {$data: '1/pattern'}}
  }
};

describe('CVE-2025-69873: ReDoS Attack Scenario', function() {
  itRe2('should prevent ReDoS with RE2 engine for $data pattern injection', function() {
    var ajv = new Ajv({$data: true, code: {regExp: re2}});
    var validate = ajv.compile(SCHEMA);

    // CVE-2025-69873 attack payload:
    //   pattern: ^(a|a)*$  -- catastrophic-backtracking regex
    //   value:  30 a's + X -- forces full exploration of exponential paths
    var maliciousPayload = {
      pattern: '^(a|a)*$',
      value: new Array(31).join('a') + 'X'
    };

    var start = Date.now();
    var result = validate(maliciousPayload);
    var elapsed = Date.now() - start;

    // Pattern doesn't match -> validation fails
    result.should.equal(false);
    // With RE2 this is linear-time; without RE2 native engine would hang for
    // many seconds.
    elapsed.should.be.below(500);
  });

  it('should handle pattern injection gracefully with default engine', function() {
    var ajv = new Ajv({$data: true});
    var validate = ajv.compile(SCHEMA);

    // Reduced payload (20 a's) so this test does not actually trigger
    // catastrophic backtracking on the native engine -- we are only verifying
    // here that the default code path completes and returns a boolean.
    // ReDoS protection itself is exercised in the RE2 test above.
    var maliciousPayload = {
      pattern: '^(a|a)*$',
      value: new Array(21).join('a') + 'X'
    };

    var result = validate(maliciousPayload);
    result.should.be.a('boolean');
  });

  itRe2('should handle multiple ReDoS patterns gracefully', function() {
    var ajv = new Ajv({$data: true, code: {regExp: re2}});
    var validate = ajv.compile(SCHEMA);

    var redosPatterns = ['^(a+)+$', '^(a|a)*$', '^(a|ab)*$', '(x+x+)+y', '(a*)*b'];

    for (var i = 0; i < redosPatterns.length; i++) {
      var pattern = redosPatterns[i];
      var start = Date.now();
      var result = validate({
        pattern: pattern,
        value: new Array(26).join('a') + 'X'
      });
      var elapsed = Date.now() - start;

      elapsed.should.be.below(500,
        'Pattern ' + pattern + ' took too long: ' + elapsed + 'ms');
      result.should.equal(false);
    }
  });

  it('should still validate valid patterns correctly', function() {
    var ajv = new Ajv({$data: true, code: re2 ? {regExp: re2} : undefined});
    var validate = ajv.compile(SCHEMA);

    validate({pattern: '^[a-z]+$', value: 'abc'}).should.equal(true);
    validate({pattern: '^[a-z]+$', value: 'ABC'}).should.equal(false);
    validate({pattern: '^\\d{3}-\\d{4}$', value: '123-4567'}).should.equal(true);
    validate({pattern: '^\\d{3}-\\d{4}$', value: '12-345'}).should.equal(false);
  });

  it('should fail gracefully on invalid regex syntax in pattern', function() {
    var ajv = new Ajv({$data: true, code: re2 ? {regExp: re2} : undefined});
    var validate = ajv.compile(SCHEMA);

    var invalidPatterns = [
      '[invalid',         // unclosed bracket
      '(?P<name>...)',    // Perl-style named groups (not supported by JS or RE2)
      '*invalid',         // dangling quantifier
      '\\'                // trailing backslash
    ];

    for (var i = 0; i < invalidPatterns.length; i++) {
      var pattern = invalidPatterns[i];
      var result;
      (function() { result = validate({pattern: pattern, value: 'test'}); })
        .should.not.throw();
      // Invalid regex -> the try/catch in the generated code sets valid=false
      // and the pattern check fails.
      result.should.equal(false,
        'Invalid pattern ' + JSON.stringify(pattern) + ' should fail validation');
    }
  });

  itRe2('should process attack payload with safe timing benchmark', function() {
    var ajv = new Ajv({$data: true, code: {regExp: re2}});
    var validate = ajv.compile(SCHEMA);

    var payload = {
      pattern: '^(a|a)*$',
      value: new Array(31).join('a') + 'X'
    };

    // With RE2: < 500ms (typically < 100ms).
    // Without RE2: 40+ seconds on the native engine.
    var start = Date.now();
    var result = validate(payload);
    var elapsed = Date.now() - start;

    result.should.equal(false);
    elapsed.should.be.below(500);
  });

  it('should plumb code.regExp into static (non-$data) patterns', function() {
    function Engine(src, flags) {
      Engine.calls.push({source: src, flags: flags});
      this._re = new RegExp(src, flags);
    }
    Engine.calls = [];
    Engine.prototype.test = function(s) { return this._re.test(s); };

    var ajv = new Ajv({code: {regExp: Engine}});
    var validate = ajv.compile({type: 'string', pattern: '^foo'});

    validate('foobar').should.equal(true);
    validate('barfoo').should.equal(false);
    Engine.calls.should.have.length(1);
    Engine.calls[0].source.should.equal('^foo');
  });

  if (!re2) {
    it.skip('install `re2` (optional native dep) to run live ReDoS tests', function() {});
  }
});
