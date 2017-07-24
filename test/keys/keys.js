const fs = require('fs');

function readfile(path) {
  return fs.readFileSync(__dirname + '/' + path).toString();
}

const rsaPrivateKey = readfile('rsa-correct.key');
const rsaPublicKey = readfile('rsa-correct.key.pub');
const rsaWrongPrivateKey = readfile('rsa-wrong.key');
const rsaWrongPublicKey = readfile('rsa-wrong.key.pub');

exports.rsaPrivateKey = rsaPrivateKey;
exports.rsaPublicKey = rsaPublicKey;
exports.rsaWrongPrivateKey = rsaWrongPrivateKey;
exports.rsaWrongPublicKey = rsaWrongPublicKey;
