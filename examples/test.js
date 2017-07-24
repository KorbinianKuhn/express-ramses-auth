var express = require('express');
var ramses = require('..');

var app = express();

var isRevokedFunction = function (ticket) {
  return false;
}

app.use(ramses({
  key: "key",
  isRevoked: isRevokedFunction
}));

app.get('/', function (req, res) {
  res.send('Hello World!');
});

app.listen(3000, function () {
  console.log('Example app listening on port 3000!');
});
