/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , OAuth = require("oauth").OAuth;


/**
 * `OAuthStrategy` constructor.
 *
 * @api public
 */
function OAuthStrategy(options, validate) {
  options = options || {}
  passport.Strategy.call(this);
  
  if (!options.requestTokenURL) throw new Error('OAuthStrategy requires a requestTokenURL option');
  if (!options.accessTokenURL) throw new Error('OAuthStrategy requires a accessTokenURL option');
  if (!options.consumerKey) throw new Error('OAuthStrategy requires a consumerKey option');
  if (!options.consumerSecret) throw new Error('OAuthStrategy requires a consumerSecret option');
  if (!options.userAuthorizationURL) throw new Error('OAuthStrategy requires a userAuthorizationURL option');
  
  this._oauth = new OAuth(options.requestTokenURL, options.accessTokenURL,
                          options.consumerKey,  options.consumerSecret,
                          "1.0", options.callback || null, "HMAC-SHA1");
  this._userAuthorizationURL = options.userAuthorizationURL;
  this._validate = validate;
  
  if (options.callback && options.callback !== 'oob') {
    this.middleware.push(require('../middleware/oauthCallback')(options.callback))
  }
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(OAuthStrategy, passport.Strategy);


OAuthStrategy.prototype.authenticate = function(req) {
  var self = this;
  
  if (!req.auth || (!req.auth.oauthToken && !req.auth.oauthVerifier)) {
    this._oauth.getOAuthRequestToken(function(err, token, tokenSecret, options) {
      if (err) { return self.error(err); }

      // TODO: throw error if a session is not available
      if (!req.session['oauth']) { req.session['oauth'] = {}; }
      req.session['oauth']['oauth_token'] = token;
      req.session['oauth']['oauth_token_secret'] = tokenSecret;

      var url = self._userAuthorizationURL + '?oauth_token=' + token;
      self.redirect(url);
    });
  } else {
    this._oauth.getOAuthAccessToken(req.auth.oauthToken, req.session.oauth["oauth_token_secret"], function(err, token, tokenSecret, params) {
      if (err) { return self.error(err); }
      
      self._validate(token, tokenSecret, params, function(err, user) {
        // FIXME: unauthorized() is incorrect here, need to error or redirect
        if (err || !user) { return self.unauthorized(); }
        self.success(user);
      });
    });
  }
}


/**
 * Expose `OAuthStrategy`.
 */ 
module.exports = OAuthStrategy;
