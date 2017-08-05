const fs = require('fs');

function readfile(path) {
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const privateKeyAuth = readfile('rsa-auth.key');
const publicKeyAuth = readfile('rsa-auth.key.pub');
const privateKeyTicket = readfile('rsa-ticket.key');
const publicKeyTicket = readfile('rsa-ticket.key.pub');
const privateKeyServiceA = readfile('rsa-service-a.key');
const publicKeyServiceA = readfile('rsa-service-a.key.pub');

exports.privateKeyAuth = privateKeyAuth;
exports.publicKeyAuth = publicKeyAuth;
exports.privateKeyTicket = privateKeyTicket;
exports.publicKeyTicket = publicKeyTicket;
exports.privateKeyServiceA = privateKeyServiceA;
exports.publicKeyServiceA = publicKeyServiceA;
