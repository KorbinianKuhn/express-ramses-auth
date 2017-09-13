const ramses = require('..');
const assert = require('assert');

describe('getToken', function () {

  it('wrong header should throw', function () {
    ramses.getToken('wrong', function (err, token) {
      assert.equal(err.code, 'missing_authorization_header');
    });
  });

  it('missing authorization in header should throw', function () {
    ramses.getToken({
      headers: 'wrong'
    }, function (err, token) {
      assert.equal(err.code, 'missing_authorization_header');
    });
  });

  it('wrong authorization header format should throw', function () {
    ramses.getToken({
      headers: {
        authorization: 'wrong'
      }
    }, function (err, token) {
      assert.equal(err.code, 'credentials_bad_format');
    });
  });

  it('wrong authorization header scheme should throw', function () {
    ramses.getToken({
      headers: {
        authorization: 'wrong header'
      }
    }, function (err, token) {
      assert.equal(err.code, 'credentials_bad_scheme');
    });
  });

  it('correct authorization header should verify', function () {
    ramses.getToken({
      headers: {
        authorization: 'Bearer token'
      }
    }, function (err, token) {
      assert.equal(err, null);
      assert.equal(token, 'token');
    });
  });

});
