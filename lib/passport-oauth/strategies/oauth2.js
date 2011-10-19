/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , OAuth2 = require('oauth').OAuth2
  , OAuthError = require('../errors/oautherror');
  

function OAuth2Strategy(options, verify) {
  options = options || {}
  passport.Strategy.call(this);
  this.name = 'oauth2';
  this.verify = verify;
  
  if (!options.authorizationURL) throw new Error('OAuth2Strategy requires a authorizationURL option');
  if (!options.tokenURL) throw new Error('OAuthStrategy requires a tokenURL option');
  if (!options.clientID) throw new Error('OAuth2Strategy requires a clientID option');
  if (!options.clientSecret) throw new Error('OAuth2Strategy requires a clientSecret option');

  // NOTE: The _oauth2 property is considered "protected".  Subclasses are
  //       allowed to use it when making protected resource requests to retrieve
  //       the user profile.
  this._oauth2 = new OAuth2(options.clientID,  options.clientSecret,
                            '', options.authorizationURL, options.tokenURL);

  this._callbackURL = options.callbackURL;
  this._shouldLoadProfile = options.shouldLoadProfile || true;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(OAuth2Strategy, passport.Strategy);


/**
 * Authenticate request by delegating to a service provider using OAuth 2.0.
 *
 * @param {Object} req
 * @api protected
 */
OAuth2Strategy.prototype.authenticate = function(req) {
  var self = this;
  
  if (req.query && req.query.code) {
    var code = req.query.code;
    
    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the percent-encoded data sent in
    //       the body of the access token request.  This appears to be an
    //       artifact from an earlier draft of OAuth 2.0 (draft 22, as of the
    //       time of this writing).  This parameter is not necessary, but its
    //       presence does not appear to cause any issues.
    this._oauth2.getOAuthAccessToken(code, { grant_type: 'authorization_code', redirect_uri: this._callbackURL },
      function(err, accessToken, refreshToken) {
        if (err) { return self.error(new OAuthError('failed to obtain access token', err)); }
        
        self._loadUserProfile(accessToken, function(err, profile) {
          if (err) { return self.error(err); };
          
          self.verify(accessToken, refreshToken, profile, function(err, user) {
            if (err) { return self.error(err); }
            if (!user) { return self.fail(); }
            self.success(user, profile);
          });
        });
      }
    );
  } else {
    // TODO: Implement support for (dynamic) scopes (by passing options as a
    //       function argument)
    
    // NOTE: The module oauth (0.9.5), which is a dependency, automatically adds
    //       a 'type=web_server' parameter to the query portion of the URL.
    //       This appears to be an artifact from an earlier draft of OAuth 2.0
    //       (draft 22, as of the time of this writing).  This parameter is not
    //       necessary, but its presence does not appear to cause any issues.
    var url = this._oauth2.getAuthorizeUrl({ response_type: 'code',
                                             redirect_uri: this._callbackURL });
    this.redirect(url);
  }
}

OAuth2Strategy.prototype.userProfile = function(accessToken, done) {
  return done(null, {});
}

OAuth2Strategy.prototype._loadUserProfile = function(accessToken, done) {
  if (this._shouldLoadProfile == false) { return done(null, {}); }
  if (this._shouldLoadProfile == true) { return this.userProfile(accessToken, done); }
  // TODO: Implement support for supplying a shouldLoadProfile option as a function.
  //if (typeof this._shouldLoadProfile == 'function') {
  //  var should = 
  //} else {
  //  return done(null);
  //}
  
  return done(null, {});
}


/**
 * Expose `OAuth2Strategy`.
 */ 
module.exports = OAuth2Strategy;

