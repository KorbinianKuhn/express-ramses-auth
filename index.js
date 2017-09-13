const middleware = require('./src/middleware');
const proof = require('./src/proof');
const ramses = require('ramses-auth');

exports.getToken = require('./src/get_token');
exports.middleware = middleware;
exports.createProof = proof.createProof;
exports.verifyProof = proof.verifyProof;

exports.sign = ramses.sign;
exports.decode = ramses.decode;
exports.verify = ramses.verify;
exports.validate = ramses.validate;
