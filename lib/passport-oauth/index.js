/**
 * Module dependencies.
 */
var OAuthStrategy = require('./strategies/oauth');
var OAuth2Strategy = require('./strategies/oauth2');


/**
 * Framework version.
 */
exports.version = '0.1.1';

/**
 * Expose constructors.
 */
exports.OAuthStrategy = OAuthStrategy;
exports.OAuth2Strategy = OAuth2Strategy;
