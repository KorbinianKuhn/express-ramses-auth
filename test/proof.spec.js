const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys');
const ramsesAuth = require('../../ramses-auth');

var jwtWithoutJti = ramsesAuth.sign({
    key: 'value'
  },
  keys.rsaPrivateKey
)
var authorizationHeaderWithoutJti = `Bearer ${jwtWithoutJti}`;

var jwtWithJti = ramsesAuth.sign({
    key: 'value',
    jti: '1234'
  },
  keys.rsaPrivateKey
)

var authorizationHeaderWithJti = `Bearer ${jwtWithJti}`;

test('ramses.createProof()', function (t) {

  t.throws(function () {
    ramses.createProof('badformat', keys.rsaPrivateKey);
  }, "should throw with bad credentials format in authorization header");

  t.throws(function () {
    ramses.createProof('bad scheme', keys.rsaPrivateKey);
  }, "should throw with bad credentials format in authorization header");


  t.throws(function () {
    ramses.createProof(authorizationHeaderWithoutJti, keys.rsaPrivateKey);
  }, "should throw if parent has no jti claim");

  t.ok(typeof (ramses.createProof(authorizationHeaderWithJti, keys.rsaPrivateKey)) == "string", "proof should be string");

  t.end();
});

test('ramses.verifyProof()', function (t) {
  const proof = ramses.createProof(authorizationHeaderWithJti, keys.rsaPrivateKey);

  t.throws(function () {
    ramses.verifyProof(authorizationHeaderWithoutJti, proof, keys.rsaPublicKey);
  }, "should throw if parent has no jti claim");

  t.ok(ramses.verifyProof(authorizationHeaderWithJti, proof, keys.rsaPublicKey), "correct key must verify");
  t.notok(ramses.verifyProof(authorizationHeaderWithJti, proof, keys.rsaWrongPublicKey), "wrong key must not verify");
  t.notok(ramses.verifyProof(authorizationHeaderWithJti, "wrong proof", keys.rsaPublicKey), "wrong proof must not verify");

  t.end();
});
