/**
 * Module dependencies.
 */
var OAuthStrategy = require('./strategies/oauth');
var OAuth2Strategy = require('./strategies/oauth2');
var InternalOAuthError = require('./errors/internaloautherror');


/**
 * Expose constructors.
 */
exports.OAuthStrategy = OAuthStrategy;
exports.OAuth2Strategy = OAuth2Strategy;

exports.InternalOAuthError = InternalOAuthError;
