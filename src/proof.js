const ramses = require('ramses-auth');
const jwa = require('jwa');
const UnauthorizedError = require('./errors/UnauthorizedError');

const getToken = function (authorizationHeader) {
  var parts = authorizationHeader.split(' ');
  if (parts.length == 2) {
    var scheme = parts[0];
    var token = parts[1];

    if (/^Bearer$/i.test(scheme)) {
      return token;
    } else {
      new UnauthorizedError('credentials_bad_scheme', {
        message: 'Format is Authorization: Bearer [token]'
      })
    }
  } else {
    new UnauthorizedError('credentials_bad_format', {
      message: 'Format is Authorization: Bearer [token]'
    })
  }
}


const createProof = function (authorizationHeader, key) {
  const decodedTicket = ramses.decode(getToken(authorizationHeader));
  const algo = jwa(decodedTicket.header.alg);
  if (decodedTicket.payload.jti) {
    return algo.sign(decodedTicket.payload.jti, key);
  }
  throw new Error('Missing claim jti in ticket.')
}

const verifyProof = function (authorizationHeader, proof, key) {
  const decodedTicket = ramses.decode(getToken(authorizationHeader));
  const algo = jwa(decodedTicket.header.alg);
  if (decodedTicket.payload.jti) {
    return algo.verify(decodedTicket.payload.jti, proof, key);
  }
  throw new Error('Missing claim jti in ticket.')
}

exports.createProof = createProof;
exports.verifyProof = verifyProof;
