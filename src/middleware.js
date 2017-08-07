var UnauthorizedError = require('./errors/UnauthorizedError');
var ramses = require('../../ramses-auth');
var set = require('lodash.set');

function isFunction(object) {
  return Object.prototype.toString.call(object) === '[object Function]';
}

var ramsesMiddleware = function (options) {
  if (!options || !options.key) {
    throw new Error('verification key must be set');
  }

  var credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;

  var _requestProperty = options.requestProperty || 'user';
  var _resultProperty = options.resultProperty;

  var middleware = function (req, res, next) {
    var token;

    if (req.method === 'OPTIONS' && req.headers.hasOwnProperty('access-control-request-headers')) {
      var hasAuthInAccessControl = !!~req.headers['access-control-request-headers']
        .split(',').map(function (header) {
          return header.trim();
        }).indexOf('authorization');

      if (hasAuthInAccessControl) {
        return next();
      }
    }

    if (options.getToken && typeof options.getToken === 'function') {
      try {
        token = options.getToken(req);
      } catch (e) {
        return next(e);
      }
    } else if (req.headers && req.headers.authorization) {
      var parts = req.headers.authorization.split(' ');
      if (parts.length == 2) {
        var scheme = parts[0];
        var credentials = parts[1];

        if (/^Bearer$/i.test(scheme)) {
          token = credentials;
        } else {
          if (credentialsRequired) {
            return next(new UnauthorizedError('credentials_bad_scheme', {
              message: 'Format is Authorization: Bearer [token]'
            }));
          } else {
            return next();
          }
        }
      } else {
        return next(new UnauthorizedError('credentials_bad_format', {
          message: 'Format is Authorization: Bearer [token]'
        }));
      }
    }

    if (!token) {
      if (credentialsRequired) {
        return next(new UnauthorizedError('credentials_required', {
          message: 'No authorization token was found'
        }));
      } else {
        return next();
      }
    }

    var dtoken;
    try {
      dtoken = ramses.decode(token, options);
    } catch (err) {
      return next(new UnauthorizedError('invalid_token', err));
    }

    var key;
    if (isFunction(options.key)) {
      key = options.key(req, dtoken);
    } else {
      key = options.key;
    }

    if (!ramses.validate(token, key, options)) {
      return next(new UnauthorizedError('invalid_token', {
        message: 'Token is invalid.'
      }));
    }

    if (options.isRevokedFunction && options.isRevokedFunction(dtoken)) {
      return next(new UnauthorizedError('revoked_token', {
        message: 'The token has been revoked.'
      }));
    }

    if (_resultProperty) {
      set(res, _resultProperty, dtoken);
    }
    set(req, _requestProperty, dtoken);

    next();
  }

  return middleware;
}

module.exports = ramsesMiddleware;
