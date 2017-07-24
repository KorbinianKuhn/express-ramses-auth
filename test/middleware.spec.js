const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys');

test('ramses.middleware(): failure tests', function (t) {

  t.throws(function () {
    ramses.middleware();
  }, "should throw with missing verification key in options");


  var req = {};
  var res = {};

  ramses.middleware({
    key: keys.rsaPublicKey
  })(req, res, function (err) {
    t.ok(err);
    t.equal(err.code, "credentials_required", "should throw if no authorization header and credentials are required")
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

  t.end();
});
