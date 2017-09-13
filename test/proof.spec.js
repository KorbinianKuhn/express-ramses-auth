const ramses = require('..');
const assert = require('assert');
const keys = require('./keys');

describe('proof', function () {

  describe('createProof', function () {

    it('missing payload should throw', function () {
      ramses.createProof({}, keys.rsaPrivateKey, function (err, proof) {
        assert.equal(err.code, 'missing_payload');
      });
    });

    it('missing payload claim jti should throw', function () {
      ramses.createProof({
        payload: {}
      }, keys.rsaPrivateKey, function (err, proof) {
        assert.equal(err.code, 'missing_claim_jti');
      });
    });

    it('missing header should throw', function () {
      ramses.createProof({
        payload: {
          jti: 'uuid'
        }
      }, keys.rsaPrivateKey, function (err, proof) {
        assert.equal(err.code, 'missing_header');
      });
    });

    it('missing payload claim jti should throw', function () {
      ramses.createProof({
        header: {},
        payload: {
          jti: 'uuid'
        }
      }, keys.rsaPrivateKey, function (err, proof) {
        assert.equal(err.code, 'missing_claim_alg');
      });
    });

    var dtoken = {
      header: {
        alg: 'RS256'
      },
      payload: {
        jti: 'uuid'
      }
    }

    it('invalid key should throw', function () {
      ramses.createProof(dtoken, 'wrong', function (err, proof) {
        assert.equal(err.code, 'sign_error');
      });
    });

    it('custom key callback should return proof', function () {
      ramses.createProof(dtoken, function (dtoken, done) {
          done(null, keys.rsaPrivateKey);
        },
        function (err, proof) {
          assert.equal(err, null);
          assert.ok(proof);
        });
    });

    it('custom key callback should throw', function () {
      ramses.createProof(dtoken, function (dtoken, done) {
          done(new Error('custom_error'));
        },
        function (err, proof) {
          assert.equal(err.message, 'custom_error');
        });
    });

    it('correct input should return proof', function () {
      ramses.createProof(dtoken, keys.rsaPrivateKey, function (err, proof) {
        assert.equal(err, null);
        assert.ok(proof);
      });
    });

  });

  describe('verifyProof', function () {
    var proof = 'UV04g3EmZzBHNKC7RxWXFD3fkCHjBEkpdEpfiaPP1OSDw7Idsk_Oof13LE6YKjz8H0beL4a0qsxHrAy60L7ACbujm6QLBsEzVcfwCfoNdJlMDmcC6m6p2EherVwqFVYUr7MpGEde0JJBpqNrXguTvSfCLcKYw8qaEi1gtbpxascXeF4GLAwlBtuCyiCkBuelDppoeGUfM4yQK0P77R1fZhagwswm8oEEV6B3Z7zLoxPO0WNQE-Wj3I1RKqWhFiSnHEStA7O4jZ4aAOewrXYXFP-1Mai10S1Kv0fRtt3phLLL4LkDT8N2pOeWtee1-j6yanRvrmbOLFQAwa7Ba6qyXw';

    it('missing payload should throw', function () {
      ramses.verifyProof({}, proof, keys.rsaPublicKey, function (err, valid) {
        assert.equal(err.code, 'missing_payload');
      });
    });

    it('missing payload claim jti should throw', function () {
      ramses.verifyProof({
        payload: {}
      }, proof, keys.rsaPublicKey, function (err, valid) {
        assert.equal(err.code, 'missing_claim_jti');
      });
    });

    it('missing header should throw', function () {
      ramses.verifyProof({
        payload: {
          jti: 'uuid'
        }
      }, proof, keys.rsaPublicKey, function (err, valid) {
        assert.equal(err.code, 'missing_header');
      });
    });

    it('missing payload claim jti should throw', function () {
      ramses.verifyProof({
        header: {},
        payload: {
          jti: 'uuid'
        }
      }, proof, keys.rsaPublicKey, function (err, valid) {
        assert.equal(err.code, 'missing_claim_alg');
      });
    });

    var dtoken = {
      header: {
        alg: 'RS256'
      },
      payload: {
        jti: 'uuid'
      }
    }

    it('invalid key should throw', function () {
      ramses.verifyProof(dtoken, proof, 'wrong', function (err, valid) {
        assert.equal(err.code, 'verification_error');
      });
    });

    it('custom key callback should verify', function () {
      ramses.verifyProof(dtoken, proof, function (dtoken, done) {
          done(null, keys.rsaPublicKey);
        },
        function (err, valid) {
          assert.equal(err, null);
          assert.ok(valid);
        });
    });

    it('custom key callback should throw', function () {
      ramses.verifyProof(dtoken, proof, function (dtoken, done) {
          done(new Error('custom_error'));
        },
        function (err, valid) {
          assert.equal(err.message, 'custom_error');
        });
    });

    it('correct input should verify', function () {
      ramses.verifyProof(dtoken, proof, keys.rsaPublicKey, function (err, valid) {
        assert.equal(err, null);
        assert.ok(valid);
      });
    });

  });

});
/*const test = require('tape');
const ramses = require('..');
const keys = require('./keys/keys');
const ramsesAuth = require('ramses-auth');

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
*/
