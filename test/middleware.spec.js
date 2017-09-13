const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys');
const UnauthorizedError = require('../src/errors/UnauthorizedError');
const lodash = require("lodash");

test('ramses.middleware()', function (t) {

  var req = {};
  var res = {};

  t.throws(function () {
    ramses.middleware()(req, res, function (err) {
      t.ok(err);
      t.equals(err.code, 'verification key must be set')
    });
  }, "should throw with missing verification key in options");

  ramses.middleware({
    key: keys.rsaPublicKey
  })(req, res, function (err) {
    t.ok(err);
    t.equal(err.code, "credentials_required", "should throw if no authorization header and credentials are required");
  })

  ramses.middleware({
    key: keys.rsaPublicKey,
    credentialsRequired: false
  })(req, res, function (err) {
    t.ok(!err, "should next if no authorization header and credentials are not required");
  })

  req.originalUrl = '/skip'
  ramses.middleware({
    key: keys.rsaPublicKey,
  }).unless({
    path: '/skip'
  })(req, res, function (err) {
    t.ok(!err, "support unless skip");
  })

  var corsReq = {
    method: 'OPTIONS',
    headers: {
      'access-control-request-headers': 'sasa, sras,  authorization'
    }
  };
  ramses.middleware({
    key: keys.rsaPublicKey
  })(corsReq, res, function (err) {
    t.ok(!err, 'should skip on CORS preflight');
  });

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
    t.ok(!err, 'should next on CORS preflight with auth in access controll');
  });


  req.headers = {};
  req.headers.authorization = 'wrong';
  ramses.middleware({
    key: keys.rsaPublicKey
  })(req, res, function (err) {
    t.ok(err);
    t.equal(err.code, 'credentials_bad_format', 'should throw if authorization header is malformed')
  });

  req.headers = {};
  req.headers.authorization = 'Basic foobar';
  ramses.middleware({
    key: keys.rsaPublicKey
  })(req, res, function (err) {
    t.ok(err);
    t.equal(err.code, 'credentials_bad_scheme', 'should throw if authorization header is not Bearer')
  });

  req.headers = {};
  req.headers.authorization = 'Basic foobar';
  ramses.middleware({
    key: keys.rsaPublicKey,
    credentialsRequired: false
  })(req, res, function (err) {
    t.ok(!err, 'should next if authorization header is not Bearer and credentialsRequired is false');
  });

  req.headers = {};
  req.headers.authorization = 'Bearer wrong';
  ramses.middleware({
    key: keys.rsaPublicKey
  })(req, res, function (err) {
    t.ok(err);
    t.equals(err.code, 'invalid_token', 'should throw if authorization header is not well-formatted jwt');
  });

  req.headers = {};
  req.headers.authorization = `Bearer ${ramses.sign('wrong', keys.rsaPrivateKey)}`;
  ramses.middleware({
    key: keys.rsaPublicKey
  })(req, res, function (err) {
    t.ok(err);
    t.equals(err.code, 'invalid_token', 'should throw if jwt is an invalid json');
  });

  req.headers = {};
  req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
  ramses.middleware({
    key: keys.rsaWrongPublicKey
  })(req, res, function (err) {
    t.ok(err);
    t.equals(err.message, 'Token is invalid.', 'should throw if authorization header is not valid jwt');
  });

  req.headers = {};
  req.headers.authorization = `Bearer ${ramses.sign({aud: 'Audience'}, keys.rsaPrivateKey)}`;
  ramses.middleware({
    key: keys.rsaPublicKey,
    aud: 'Wrong Audience'
  })(req, res, function (err) {
    t.ok(err);
    t.equals(err.message, 'Token is invalid.', 'should throw if audience is not expected');
  });

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
    t.ok(err);
    t.equals(err.code, 'custom_invalid_token', 'should use errors thrown from custom getToken function');
  });


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
    t.ok(!err, 'should verify with getKey function');
  });

  req.headers = {};
  req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
  ramses.middleware({
    key: keys.rsaPublicKey,
    isRevoked: function (req, dtoken, done) {
      done(new Error('An error ocurred'));
    }
  })(req, res, function (err) {
    t.ok(err);
    t.equals(err.message, 'An error ocurred', 'should throw if revoked token function throws error');
  });

  req.headers = {};
  req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
  ramses.middleware({
    key: keys.rsaPublicKey,
    isRevoked: function (req, dtoken, done) {
      done(null, true);
    }
  })(req, res, function (err) {
    t.ok(err);
    t.equals(err.code, 'revoked_token', 'should throw if token is revoked');
  });

  req.headers = {};
  req.headers.authorization = `Bearer ${ramses.sign({foo: 'bar'}, keys.rsaPrivateKey)}`;
  ramses.middleware({
    key: keys.rsaPublicKey,
    isRevoked: function (req, dtoken, done) {
      done(null, false);
    }
  })(req, res, function (err) {
    t.ok(!err, 'should not throw if token is not revoked');
  });

  token = ramses.sign({
    foo: 'bar'
  }, keys.rsaPrivateKey);
  dtoken = ramses.decode(token);
  req.headers = {};
  req.headers.authorization = `Bearer ${token}`;
  ramses.middleware({
    key: keys.rsaPublicKey
  })(req, res, function (err) {
    t.ok(lodash.isEqual(req.user, dtoken), 'req should contain decoded token under default property user');
  });

  ramses.middleware({
    key: keys.rsaPublicKey,
    requestProperty: 'customProperty'
  })(req, res, function (err) {
    t.ok(lodash.isEqual(req.customProperty, dtoken), 'req should contain decoded token under custom property');
  });

  ramses.middleware({
    key: keys.rsaPublicKey,
    resultProperty: 'user'
  })(req, res, function (err) {
    t.ok(lodash.isEqual(res.user, dtoken), 'res should contain decoded token under custom property');
  });

  t.end();
});
