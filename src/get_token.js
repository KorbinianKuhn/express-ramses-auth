const UnauthorizedError = require('./errors/UnauthorizedError');

module.exports = function (req, callback) {
  if (!req.headers || !req.headers.authorization) {
    return callback(new UnauthorizedError('missing_authorization_header', {
      message: 'Missing authorization header. Format is Authorization: Bearer [token]'
    }));
  }
  var parts = req.headers.authorization.split(' ');

  if (parts.length !== 2) {
    return callback(new UnauthorizedError('credentials_bad_format', {
      message: 'Format is Authorization: Bearer [token]'
    }));
  }
  var scheme = parts[0];
  var credentials = parts[1];

  if (/^Bearer$/i.test(scheme)) {
    return callback(null, credentials);
  } else {
    return callback(new UnauthorizedError('credentials_bad_scheme', {
      message: 'Format is Authorization: Bearer [token]'
    }));
  }
}
