/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , OAuth = require('oauth').OAuth
  , OAuthError = require('../errors/oautherror');


/**
 * `OAuthStrategy` constructor.
 *
 * @api public
 */
function OAuthStrategy(options, verify) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'oauth';
  this.verify = verify;
  
  if (!options.requestTokenURL) throw new Error('OAuthStrategy requires a requestTokenURL option');
  if (!options.accessTokenURL) throw new Error('OAuthStrategy requires a accessTokenURL option');
  if (!options.consumerKey) throw new Error('OAuthStrategy requires a consumerKey option');
  if (!options.consumerSecret) throw new Error('OAuthStrategy requires a consumerSecret option');
  if (!options.userAuthorizationURL) throw new Error('OAuthStrategy requires a userAuthorizationURL option');
  
  this._oauth = new OAuth(options.requestTokenURL, options.accessTokenURL,
                          options.consumerKey,  options.consumerSecret,
                          "1.0", options.callback || null, "HMAC-SHA1");
  this._userAuthorizationURL = options.userAuthorizationURL;
  this._key = options.sessionKey || 'oauth';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(OAuthStrategy, passport.Strategy);


OAuthStrategy.prototype.authenticate = function(req) {
  if (!req.session) { return this.error(new Error('OAuth authentication requires session support')); }
  
  var self = this;
  
  if (req.query && req.query['oauth_token']) {
    // The request being authenticated contains an oauth_token parameter in the
    // query portion of the URL.  This indicates that the service provider has
    // redirected the user back to the application, after authenticating the
    // user and obtaining their authorization.
    //
    // The value of the oauth_token parameter is the request token.  Together
    // with knowledge of the token secret (stored in the session), the request
    // token can be exchanged for an access token and token secret.
    //
    // This access token and token secret, along with the optional ability to
    // fetch profile information from the service provider, is sufficient to
    // establish the identity of the user.
    var oauthToken = req.query['oauth_token'];
    var oauthVerifier = req.query['oauth_verifier'] || null;
    
    // NOTE: The oauth_verifier parameter will be supplied in the query portion
    //       of the redirect URL, if the server supports OAuth 1.0a.
    
    // TODO: When OAuth authorization is denied, Twitter allows the user to
    //       click a link in the following format:
    //       /auth/twitter/callback?denied=<request_token>
    //       Implement support for this pattern.
    
    this._oauth.getOAuthAccessToken(oauthToken, req.session[self._key]["oauth_token_secret"], oauthVerifier, function(err, token, tokenSecret, params) {
      if (err) { return self.error(new OAuthError('failed to obtain access token', err)); }
      
      // The request token has been exchanged for an access token.  Since the
      // request token is a single-use token, that data can be removed from the
      // session.
      delete req.session[self._key]['oauth_token'];
      delete req.session[self._key]['oauth_token_secret'];
      if (Object.keys(req.session[self._key]).length == 0) {
        delete req.session[self._key];
      }
      
      self.verify(token, tokenSecret, params, function(err, user) {
        if (err) { return self.error(err); }
        if (!user) { return self.fail(); }
        // TODO: pass params (or user info) to success
        self.success(user);
      });
    });
  } else {
    // In order to authenticate via OAuth, the application must obtain a request
    // token from the service provider and redirect the user to the service
    // provider to obtain their authorization.  After authorization has been
    // approved the user will be redirected back the application, at which point
    // the application can exchange the request token for an access token.
    //
    // In order to successfully exchange the request token, its corresponding
    // token secret needs to be known.  The token secret will be temporarily
    // stored in the session, so that it can be retrieved upon the user being
    // redirected back to the application.
    this._oauth.getOAuthRequestToken(function(err, token, tokenSecret, options) {
      if (err) { return self.error(new OAuthError('failed to obtain request token', err)); }
      
      // NOTE: options will contain an oauth_callback_confirmed property set to
      //       true, if the server supports OAuth 1.0a.
      //       { oauth_callback_confirmed: 'true' }

      if (!req.session[self._key]) { req.session[self._key] = {}; }
      req.session[self._key]['oauth_token'] = token;
      req.session[self._key]['oauth_token_secret'] = tokenSecret;

      var url = self._userAuthorizationURL + '?oauth_token=' + token;
      self.redirect(url);
    });
  }
}


/**
 * Expose `OAuthStrategy`.
 */ 
module.exports = OAuthStrategy;
