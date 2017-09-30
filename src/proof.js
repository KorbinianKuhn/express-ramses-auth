const ramses = require('ramses-auth');
const jwa = require('jwa');
const UnauthorizedError = require('./errors/UnauthorizedError');
const getToken = require('./get_token');

const isFunction = function (object) {
  return Object.prototype.toString.call(object) === '[object Function]';
}




const createProof = function (message, key, options, callback) {
  if (isFunction(options)) {
    callback = options;
    options = {};
  }

  if (options.alg && ramses.ALGORITHMS.indexOf(options.alg) == -1) {
    return callback(new UnauthorizedError('invalid_algorithm', {
      message: 'Invalid value for parameter alg'
    }));
  }
  alg = options.alg || 'RS256';

  var proof;
  try {
    const algo = jwa(alg);
    proof = algo.sign(message, key);
  } catch (err) {
    return callback(new UnauthorizedError('sign_error', {
      message: err.message
    }));
  }

  return callback(null, proof);
}

const verifyProof = function (message, proof, key, options, callback) {
  if (isFunction(options)) {
    callback = options;
    options = {};
  }

  if (options.alg && ramses.ALGORITHMS.indexOf(options.alg) == -1) {
    return callback(new UnauthorizedError('invalid_algorithm', {
      message: 'Invalid value for parameter alg'
    }));
  }
  alg = options.alg || 'RS256';

  var verified;
  const algo = jwa(alg);
  try {
    verified = algo.verify(message, proof, key);
  } catch (err) {
    return callback(new UnauthorizedError('verification_error', {
      message: err.message
    }));
  }

  return callback(null, verified);
}

exports.createProof = createProof;
exports.verifyProof = verifyProof;
