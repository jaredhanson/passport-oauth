/**
 * Module dependencies.
 */
var OAuthStrategy = require('./strategies/oauth')
  , OAuth2Strategy = require('./strategies/oauth2')
  , InternalOAuthError = require('./errors/internaloautherror');


/**
 * Export constructors.
 */
exports.OAuthStrategy = OAuthStrategy;
exports.OAuth2Strategy = OAuth2Strategy;

/**
 * Export errors.
 */
exports.InternalOAuthError = InternalOAuthError;
