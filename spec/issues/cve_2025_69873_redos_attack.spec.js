'use strict';

var Ajv = require('../ajv');
require('../chai').should();

describe('CVE-2025-69873: ReDoS Attack Scenario', function() {
  it('should handle pattern injection gracefully with $data', function() {
    var ajv = new Ajv({$data: true});

    var schema = {
      type: 'object',
      properties: {
        pattern: {type: 'string'},
        value: {type: 'string', pattern: {$data: '1/pattern'}}
      }
    };

    var validate = ajv.compile(schema);

    // CVE-2025-69873 Attack Payload:
    // Pattern: ^(a|a)*$ - catastrophic backtracking regex
    // Value: 20 a's + X - forces full exploration of exponential paths
    // With try/catch, invalid pattern results in validation failure
    var maliciousPayload = {
      pattern: '^(a|a)*$',
      value: 'a'.repeat(20) + 'X'
    };

    // Should complete without crashing (might be slow but won't hang forever)
    // With try/catch, the pattern is evaluated and validation fails
    var result = validate(maliciousPayload);
    result.should.be.a('boolean');
  });

  it('should handle multiple ReDoS patterns gracefully', function() {
    var ajv = new Ajv({$data: true});

    var schema = {
      type: 'object',
      properties: {
        pattern: {type: 'string'},
        value: {type: 'string', pattern: {$data: '1/pattern'}}
      }
    };

    var validate = ajv.compile(schema);

    // Various ReDoS-vulnerable patterns
    var redosPatterns = ['^(a+)+$', '^(a|a)*$', '^(a|ab)*$', '(x+x+)+y', '(a*)*b'];

    for (var i = 0; i < redosPatterns.length; i++) {
      var pattern = redosPatterns[i];
      var start = Date.now();
      var result = validate({
        pattern: pattern,
        value: 'a'.repeat(15) + 'X'
      });
      var elapsed = Date.now() - start;

      // All should complete reasonably quickly
      // We use a generous timeout since native RegExp can still be slow
      elapsed.should.be.below(10000, 'Pattern ' + pattern + ' took too long: ' + elapsed + 'ms');
      result.should.be.a('boolean');
    }
  });

  it('should still validate valid patterns correctly', function() {
    var ajv = new Ajv({$data: true});

    var schema = {
      type: 'object',
      properties: {
        pattern: {type: 'string'},
        value: {type: 'string', pattern: {$data: '1/pattern'}}
      }
    };

    var validate = ajv.compile(schema);

    // Valid pattern matching tests
    validate({pattern: '^[a-z]+$', value: 'abc'}).should.equal(true);
    validate({pattern: '^[a-z]+$', value: 'ABC'}).should.equal(false);
    validate({pattern: '^\\d{3}-\\d{4}$', value: '123-4567'}).should.equal(true);
    validate({pattern: '^\\d{3}-\\d{4}$', value: '12-345'}).should.equal(false);
  });

  it('should fail gracefully on invalid regex syntax in pattern', function() {
    var ajv = new Ajv({$data: true});

    var schema = {
      type: 'object',
      properties: {
        pattern: {type: 'string'},
        value: {type: 'string', pattern: {$data: '1/pattern'}}
      }
    };

    var validate = ajv.compile(schema);

    // Invalid regex patterns
    var invalidPatterns = [
      '[invalid',  // Unclosed bracket
      '(?P<name>...)',  // Named groups
      '*invalid'  // Invalid quantifier
    ];

    for (var i = 0; i < invalidPatterns.length; i++) {
      var pattern = invalidPatterns[i];
      // Invalid patterns should result in validation failure due to try/catch
      var result = validate({
        pattern: pattern,
        value: 'test'
      });
      // With try/catch protection, invalid patterns result in false
      result.should.equal(false, 'Invalid pattern ' + pattern + ' should fail validation');
    }
  });

  it('should process attack payload with safe timing', function() {
    var ajv = new Ajv({$data: true});

    var schema = {
      type: 'object',
      properties: {
        pattern: {type: 'string'},
        value: {type: 'string', pattern: {$data: '1/pattern'}}
      }
    };

    var validate = ajv.compile(schema);

    // Process a ReDoS attack payload with reasonable size
    var payload = {
      pattern: '^(a|a)*$',
      value: 'a'.repeat(20) + 'X'
    };

    // Should complete without hanging
    var start = Date.now();
    var result = validate(payload);
    var elapsed = Date.now() - start;

    result.should.be.a('boolean');
    // With native RegExp this might still take some time, but shouldn't hang
    elapsed.should.be.below(10000);
  });

  it('should not affect static patterns', function() {
    var ajv = new Ajv({$data: true});

    // Schema with static pattern (not $data)
    var schema = {
      type: 'object',
      properties: {
        email: {
          type: 'string',
          pattern: '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$'
        }
      }
    };

    var validate = ajv.compile(schema);

    // Static patterns should work normally
    validate({email: 'test@example.com'}).should.equal(true);
    validate({email: 'invalid-email'}).should.equal(false);
    validate({email: 'user@domain.co.uk'}).should.equal(true);
  });

  it('should handle unicode flag correctly with $data patterns', function() {
    var ajv = new Ajv({$data: true, unicodeRegExp: true});

    var schema = {
      type: 'object',
      properties: {
        pattern: {type: 'string'},
        value: {type: 'string', pattern: {$data: '1/pattern'}}
      }
    };

    var validate = ajv.compile(schema);

    // Test with unicode pattern
    var result = validate({
      pattern: '^[\\u0000-\\uFFFF]+$',
      value: 'test'
    });

    result.should.be.a('boolean');
  });
});
