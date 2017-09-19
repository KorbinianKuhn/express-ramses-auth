const assert = require('assert');
const ramses = require('..');
const keys = require('./keys');
const UnauthorizedError = require('../src/errors/UnauthorizedError');
const lodash = require("lodash");

describe('middleware', function () {

  var req = {};
  var res = {};

  it('should throw with missing verification key in options', function () {
    try {
      ramses.middleware();
    } catch (e) {
      assert.ok(e);
      assert.equal(e.message, 'verification key must be set');
    }
  });

  it('should throw if no authorization header and credentials are required', function () {
    ramses.middleware({
      key: keys.rsaPublicKey
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_required');
    });
  });

  it('should next if no authorization header and credentials are not required', function () {
    ramses.middleware({
      key: keys.rsaPublicKey,
      credentialsRequired: false
    })(req, res, function (err) {
      assert.ok(!err);
    });
  });

  it('support unless skip', function () {
    req.originalUrl = '/skip'
    ramses.middleware({
      key: keys.rsaPublicKey,
    }).unless({
      path: '/skip'
    })(req, res, function (err) {
      assert.ok(!err);
    })
  });

  it('should skip on CORS preflight', function () {
    var corsReq = {
      method: 'OPTIONS',
      headers: {
        'access-control-request-headers': 'sasa, sras,  authorization'
      }
    };
    ramses.middleware({
      key: keys.rsaPublicKey
    })(corsReq, res, function (err) {
      assert.ok(!err);
    });
  });

  it('should next on CORS preflight with auth in access control', function () {
    corsReq = {
      method: 'OPTIONS',
      headers: {
        'access-control-request-headers': 'sasa, sras'
      }
    };
    ramses.middleware({
      key: keys.rsaPublicKey,
      credentialsRequired: false
    })(corsReq, res, function (err) {
      assert.ok(!err);
    });
  });

  it('should throw if authorization header is malformed', function () {
    req.headers = {};
    req.headers.authorization = 'wrong';
    ramses.middleware({
      key: keys.rsaPublicKey
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_bad_format')
    });
  });

  it('should throw if authorization header is not Bearer', function () {
    req.headers = {};
    req.headers.authorization = 'Basic foobar';
    ramses.middleware({
      key: keys.rsaPublicKey
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'credentials_bad_scheme')
    });
  });

  it('should next if authorization header is not Bearer and credentialsRequired is false', function () {
    req.headers = {};
    req.headers.authorization = 'Basic foobar';
    ramses.middleware({
      key: keys.rsaPublicKey,
      credentialsRequired: false
    })(req, res, function (err) {
      assert.ok(!err);
    });
  });

  it('should throw if authorization header is not well-formatted jwt', function () {
    req.headers = {};
    req.headers.authorization = 'Bearer wrong';
    ramses.middleware({
      key: keys.rsaPublicKey
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'decoding_error');
    });
  });

  it('should throw if jwt is an invalid json', function () {
    req.headers = {};
    req.headers.authorization = `Bearer ${ramses.sign('wrong', keys.rsaPrivateKey)}`;
    ramses.middleware({
      key: keys.rsaPublicKey
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
    });
  });

  it('should throw if authorization header is not valid jwt', function () {
    req.headers = {};
    req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
    ramses.middleware({
      key: keys.rsaWrongPublicKey
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'invalid_token');
    });
  });

  it('should throw if audience is not as expected', function () {
    req.headers = {};
    req.headers.authorization = `Bearer ${ramses.sign({aud: 'Audience'}, keys.rsaPrivateKey)}`;
    ramses.middleware({
      key: keys.rsaPublicKey,
      aud: 'Wrong Audience'
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'wrong_audience');
    });
  });

  it('should use errors thrown from custom getToken function', function () {
    function getTokenThatThrowsError() {
      throw new UnauthorizedError('custom_invalid_token', {
        message: 'Invalid token!'
      });
    }
    req.headers = {};
    req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
    ramses.middleware({
      key: keys.rsaPublicKey,
      getToken: getTokenThatThrowsError
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'custom_invalid_token');
    });
  });

  it('should verify with getKey function', function () {
    var keyCallback = function (req, dtoken, cb) {
      process.nextTick(function () {
        return cb(null, keys.rsaPublicKey)
      });
    }
    req.headers = {};
    req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
    ramses.middleware({
      key: keyCallback
    })(req, res, function (err) {
      assert.ok(!err);
    });
  });

  it('should throw if revoked token function throws error', function () {
    req.headers = {};
    req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
    ramses.middleware({
      key: keys.rsaPublicKey,
      isRevoked: function (req, dtoken, done) {
        done(new Error('An error ocurred'));
      }
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.message, 'An error ocurred');
    });
  });

  it('should throw if token is revoked', function () {
    req.headers = {};
    req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
    ramses.middleware({
      key: keys.rsaPublicKey,
      isRevoked: function (req, dtoken, done) {
        done(null, true);
      }
    })(req, res, function (err) {
      assert.ok(err);
      assert.equal(err.code, 'revoked_token');
    });
  });

  it('should not throw if token is not revoked', function () {
    req.headers = {};
    req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
    ramses.middleware({
      key: keys.rsaPublicKey,
      isRevoked: function (req, dtoken, done) {
        done(null, false);
      }
    })(req, res, function (err) {
      assert.ok(!err);
    });

  });

  it('req should contain decoded token under default property user', function () {
    token = ramses.sign({
      foo: 'bar'
    }, keys.rsaPrivateKey);
    dtoken = ramses.decode(token);
    req.headers = {};
    req.headers.authorization = `Bearer ${token}`;
    ramses.middleware({
      key: keys.rsaPublicKey
    })(req, res, function (err) {
      assert.ok(lodash.isEqual(req.user, dtoken.payload));
    });
  });

  it('req should contain decoded token under custom property', function () {
    ramses.middleware({
      key: keys.rsaPublicKey,
      requestProperty: 'customProperty'
    })(req, res, function (err) {
      assert.ok(lodash.isEqual(req.customProperty, dtoken.payload));
    });
  });

  it('res should contain decoded token under custom property', function () {
    ramses.middleware({
      key: keys.rsaPublicKey,
      resultProperty: 'user'
    })(req, res, function (err) {
      assert.ok(lodash.isEqual(res.user, dtoken.payload));
    });
  });

  it('res should contain full decoded token under default property user', function () {
    ramses.middleware({
      key: keys.rsaPublicKey,
      attachFullToken: true
    })(req, res, function (err) {
      assert.ok(lodash.isEqual(req.user, dtoken));
    });
  });
});
