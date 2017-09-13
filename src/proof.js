const ramses = require('ramses-auth');
const jwa = require('jwa');
const UnauthorizedError = require('./errors/UnauthorizedError');
const getToken = require('./get_token');

const isFunction = function (object) {
  return Object.prototype.toString.call(object) === '[object Function]';
}
const wrapStaticKeyInCallback = function (key) {
  return function (dtoken, cb) {
    return cb(null, key);
  };
}

const createProof = function (dtoken, key, callback) {
  if (!dtoken.payload) {
    return callback(new UnauthorizedError('missing_payload', {
      message: 'Token has no payload'
    }));
  }

  if (!dtoken.payload.jti) {
    return callback(new UnauthorizedError('missing_claim_jti', {
      message: 'Token has no jti claim'
    }));
  }

  if (!dtoken.header) {
    return callback(new UnauthorizedError('missing_header', {
      message: 'Token has no header'
    }));
  }

  if (!dtoken.header.alg) {
    return callback(new UnauthorizedError('missing_claim_alg', {
      message: 'Token has no alg claim'
    }));
  }

  var keyCallback = key;
  if (!isFunction(keyCallback)) {
    keyCallback = wrapStaticKeyInCallback(keyCallback);
  }

  keyCallback(dtoken, function (err, key) {
    if (err) {
      return callback(err);
    }

    var proof;
    try {
      const algo = jwa(dtoken.header.alg);
      proof = algo.sign(dtoken.payload.jti, key);
    } catch (err) {
      return callback(new UnauthorizedError('sign_error', {
        message: err.message
      }));
    }

    return callback(null, proof);
  });
}

const verifyProof = function (dtoken, proof, key, callback) {
  if (!dtoken.payload) {
    return callback(new UnauthorizedError('missing_payload', {
      message: 'Token has no payload'
    }));
  }

  if (!dtoken.payload.jti) {
    return callback(new UnauthorizedError('missing_claim_jti', {
      message: 'Token has no jti claim'
    }));
  }

  if (!dtoken.header) {
    return callback(new UnauthorizedError('missing_header', {
      message: 'Token has no header'
    }));
  }

  if (!dtoken.header.alg) {
    return callback(new UnauthorizedError('missing_claim_alg', {
      message: 'Token has no alg claim'
    }));
  }

  var keyCallback = key;
  if (!isFunction(keyCallback)) {
    keyCallback = wrapStaticKeyInCallback(keyCallback);
  }

  keyCallback(dtoken, function (err, key) {
    if (err) {
      return callback(err);
    }

    var verified;
    const algo = jwa(dtoken.header.alg);
    try {
      verified = algo.verify(dtoken.payload.jti, proof, key);
    } catch (err) {
      return callback(new UnauthorizedError('verification_error', {
        message: err.message
      }));
    }

    return callback(null, verified);
  });
}

exports.createProof = createProof;
exports.verifyProof = verifyProof;
