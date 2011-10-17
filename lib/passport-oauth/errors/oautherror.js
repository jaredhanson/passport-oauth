/**
 * `OAuthError` error.
 *
 * @api private
 */
function OAuthError(message, err) {
  Error.call(this);
  Error.captureStackTrace(this, arguments.callee);
  this.name = 'OAuthError';
  this.message = message;
  this.oauthError = err;
};

/**
 * Inherit from `Error`.
 */
OAuthError.prototype.__proto__ = Error.prototype;


/**
 * Expose `OAuthError`.
 */
module.exports = OAuthError;
