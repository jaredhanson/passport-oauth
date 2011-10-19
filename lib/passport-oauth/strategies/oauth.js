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
 * The OAuth authentication strategy authenticates requests using the OAuth
 * protocol.
 *
 * OAuth provides a facility for delegated authentication, whereby users can
 * authenticate using a third-party service such as Twitter.  Delegating in this
 * manner involves a sequence of events, including redirecting the user to the
 * third-party service for authorization.  Once authorization has been obtained,
 * the user is redirected back to the application and a token can be used to
 * obtain credentials.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `requestTokenURL`       URL used to obtain an unauthorized request token
 *   - `accessTokenURL`        URL used to exchange a user-authorized request token for an access token
 *   - `userAuthorizationURL`  URL used to obtain user authorization
 *   - `consumerKey`           identifies client to service provider
 *   - `consumerSecret`        secret used to establish ownership of the consumer key
 *   - `callbackURL`           URL to which the service provider will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new OAuthStrategy({
 *         requestTokenURL: 'https://www.example.com/oauth/request_token',
 *         accessTokenURL: 'https://www.example.com/oauth/access_token',
 *         userAuthorizationURL: 'https://www.example.com/oauth/authorize',
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/example/callback'
 *       },
 *       function(token, tokenSecret, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function OAuthStrategy(options, verify) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'oauth';
  this.verify = verify;
  
  if (!options.requestTokenURL) throw new Error('OAuthStrategy requires a requestTokenURL option');
  if (!options.accessTokenURL) throw new Error('OAuthStrategy requires a accessTokenURL option');
  if (!options.userAuthorizationURL) throw new Error('OAuthStrategy requires a userAuthorizationURL option');
  if (!options.consumerKey) throw new Error('OAuthStrategy requires a consumerKey option');
  if (!options.consumerSecret) throw new Error('OAuthStrategy requires a consumerSecret option');
  if (!verify) throw new Error('OAuth authentication strategy requires a verify function');
  
  this._oauth = new OAuth(options.requestTokenURL, options.accessTokenURL,
                          options.consumerKey,  options.consumerSecret,
                          "1.0", options.callbackURL || null, "HMAC-SHA1");
  this._userAuthorizationURL = options.userAuthorizationURL;
  this._key = options.sessionKey || 'oauth';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(OAuthStrategy, passport.Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth.
 *
 * @param {Object} req
 * @api protected
 */
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
