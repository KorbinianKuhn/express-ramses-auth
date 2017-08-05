const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys');

test('ramses.middleware(): failure tests', function (t) {

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

  t.end();
});
