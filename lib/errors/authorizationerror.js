/**
 * `AuthorizationError` error.
 *
 * @api public
 */
function AuthorizationError(message, code, uri, status) {
  if (!status) {
    switch (code) {
      case 'access_denied': status = 403; break;
      case 'server_error': status = 502; break;
      case 'temporarily_unavailable': status = 503; break;
    }
  }
  
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'AuthorizationError';
  this.message = message || 'OAuth 2.0 authorization request failed';
  this.code = code || 'server_error';
  this.uri = uri;
  this.status = status || 500;
};

/**
 * Inherit from `Error`.
 */
AuthorizationError.prototype.__proto__ = Error.prototype;


/**
 * Expose `AuthorizationError`.
 */
module.exports = AuthorizationError;
