const ramses = require('..');
const assert = require('assert');
const keys = require('./keys');

describe('proof', function () {
  const message = '4f046326-6e2f-4aa9-a95a-cade057746cc';
  const validProof = 'eY4CIfRD8q4rBfFAfqdxBaSfqM4akD8y5YQmMl1BSMHGrO_2dX_mePWCfpKEHuk0RZ8p5zusRYhmYreNwGqK026s6uyPu6exu8RPVFDBl4XT4J0nUi4Lz_ex6QhmKIwtVt34wMSWqDqncTPpewjHFCxWjLHQtMzC3UesWK49bveC9mNY03ENIq0BknQCBHdCZ-RrCURBcd7tz34R18Mj4HM2ZaZ1tyz9rTA_tGiKW2wqUQQBrRnDiGgfqVMKorIEO_HlWQyoxzSWGTDK9_QmRLN-iutrLv-JV3NR278Rdhnp0cTMB46bG6QaaOSoblNWiHBfaCh0OnEmMOtw4ojwSg'
  describe('createProof', function () {

    it('invalid key should throw', function () {
      ramses.createProof(message, 'wrong', function (err, proof) {
        assert.equal(err.code, 'sign_error');
      });
    });

    it('invalid alg should throw', function () {
      ramses.createProof(message, keys.rsaPrivateKey, {
        'alg': 'wrong'
      }, function (err, proof) {
        assert.equal(err.code, 'invalid_algorithm');
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
    it('invalid key should throw', function () {
      ramses.verifyProof(message, validProof, 'wrong', function (err, valid) {
        assert.equal(err.code, 'verification_error');
      });
    });

    it('invalid alg should throw', function () {
      ramses.verifyProof(message, validProof, keys.rsaPrivateKey, {
        'alg': 'wrong'
      }, function (err, proof) {
        assert.equal(err.code, 'invalid_algorithm');
      });
    });

    it('correct input should verify', function () {
      ramses.verifyProof(message, validProof, keys.rsaPublicKey, function (err, valid) {
        assert.equal(err, null);
        assert.ok(valid);
      });
    });

  });

});
