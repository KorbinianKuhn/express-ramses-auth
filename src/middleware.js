const UnauthorizedError = require('./errors/UnauthorizedError');
const ramses = require('ramses-auth');
const set = require('lodash.set');
const unless = require('express-unless');
const async = require('async');

var DEFAULT_REVOKED_FUNCTION = function (_, __, cb) {
  return cb(null, false);
};

function isFunction(object) {
  return Object.prototype.toString.call(object) === '[object Function]';
}

function wrapStaticKeyInCallback(secret) {
  return function (_, __, cb) {
    return cb(null, secret);
  };
}

const ramsesMiddleware = function (options) {
  if (!options || !options.key) {
    throw new Error('verification key must be set');
  }

  var keyCallback = options.key;

  if (!isFunction(keyCallback)) {
    keyCallback = wrapStaticKeyInCallback(keyCallback);
  }

  var isRevokedCallback = options.isRevoked || DEFAULT_REVOKED_FUNCTION;

  var credentialsRequired = typeof options.credentialsRequired === 'undefined' ? true : options.credentialsRequired;

  var _requestProperty = options.requestProperty || 'user';
  var _resultProperty = options.resultProperty;

  const middleware = function (req, res, next) {
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

    /*
    if (!ramses.validate(token, key, options)) {
      return next(new UnauthorizedError('invalid_token', {
        message: 'Token is invalid.'
      }));
    }
    */

    async.waterfall([
      function getKey(callback) {
        keyCallback(req, dtoken, callback);
      },
      function validateToken(key, callback) {
        if (ramses.validate(token, key, options)) {
          callback(null, true);
        } else {
          callback(new UnauthorizedError('invalid_token', {
            message: 'Token is invalid.'
          }));
        }
      },
      function checkRevoked(decoded, callback) {
        isRevokedCallback(req, dtoken, function (err, revoked) {
          if (err) {
            callback(err);
          } else if (revoked) {
            callback(new UnauthorizedError('revoked_token', {
              message: 'The token has been revoked.'
            }));
          } else {
            callback(null, decoded);
          }
        });
      }

    ], function (err, result) {
      if (err) {
        return next(err);
      }

      if (_resultProperty) {
        set(res, _resultProperty, dtoken);
      }
      set(req, _requestProperty, dtoken);

      next();

    });
  };

  middleware.unless = unless;
  middleware.UnauthorizedError = UnauthorizedError;

  return middleware;
}

module.exports = ramsesMiddleware;
