var vows = require('vows');
var assert = require('assert');
var util = require('util');
var OAuthStrategy = require('passport-oauth/strategies/oauth');


vows.describe('OAuthStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
    },
    
    'should be named session': function (strategy) {
      assert.equal(strategy.name, 'oauth');
    },
  },
  
  'strategy handling an authorized request': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function(token, tokenSecret, info, done) {
          done(null, { token: token, tokenSecret: tokenSecret });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          req.user = user;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.token, 'access-token');
        assert.equal(req.user.tokenSecret, 'access-token-secret');
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request that is not verified': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function(token, tokenSecret, info, done) {
          done(null, false);
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success' : function(err, req) {
        assert.isNull(err);
      },
      'should call fail' : function(err, req) {
        assert.isNotNull(req);
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request that encounters an error during verification': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function(token, tokenSecret, info, done) {
          done(new Error('something-went-wrong'));
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request should load user profile by default': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function(token, tokenSecret, info, done) {
          done(null, { token: token, tokenSecret: tokenSecret });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      strategy.userProfile = function(token, tokenSecret, params, done) {
        done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, profile) {
          req.user = user;
          req.profile = profile;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.token, 'access-token');
        assert.equal(req.user.tokenSecret, 'access-token-secret');
      },
      'should provide profile' : function(err, req) {
        assert.equal(req.profile.location, 'Oakland, CA');
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request should not load user profile when option is disabled': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          skipUserProfile: true
        },
        function(token, tokenSecret, info, done) {
          done(null, { token: token, tokenSecret: tokenSecret });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      strategy.userProfile = function(token, tokenSecret, params, done) {
        done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, profile) {
          req.user = user;
          req.profile = profile;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.token, 'access-token');
        assert.equal(req.user.tokenSecret, 'access-token-secret');
      },
      'should not provide profile' : function(err, req) {
        assert.isUndefined(req.profile);
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request should load user profile when function synchronously returns false': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          skipUserProfile: function() {
            return false;
          }
        },
        function(token, tokenSecret, info, done) {
          done(null, { token: token, tokenSecret: tokenSecret });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      strategy.userProfile = function(token, tokenSecret, params, done) {
        done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, profile) {
          req.user = user;
          req.profile = profile;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.token, 'access-token');
        assert.equal(req.user.tokenSecret, 'access-token-secret');
      },
      'should provide profile' : function(err, req) {
        assert.equal(req.profile.location, 'Oakland, CA');
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request should not load user profile when function synchronously returns true': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          skipUserProfile: function() {
            return true;
          }
        },
        function(token, tokenSecret, info, done) {
          done(null, { token: token, tokenSecret: tokenSecret });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      strategy.userProfile = function(token, tokenSecret, params, done) {
        done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, profile) {
          req.user = user;
          req.profile = profile;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.token, 'access-token');
        assert.equal(req.user.tokenSecret, 'access-token-secret');
      },
      'should not provide profile' : function(err, req) {
        assert.isUndefined(req.profile);
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request should load user profile when function asynchronously returns false': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          skipUserProfile: function(token, tokenSecret, done) {
            done(null, false);
          }
        },
        function(token, tokenSecret, info, done) {
          done(null, { token: token, tokenSecret: tokenSecret });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      strategy.userProfile = function(token, tokenSecret, params, done) {
        done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, profile) {
          req.user = user;
          req.profile = profile;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.token, 'access-token');
        assert.equal(req.user.tokenSecret, 'access-token-secret');
      },
      'should provide profile' : function(err, req) {
        assert.equal(req.profile.location, 'Oakland, CA');
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request should load user profile when function asynchronously returns true': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          skipUserProfile: function(token, tokenSecret, done) {
            done(null, true);
          }
        },
        function(token, tokenSecret, info, done) {
          done(null, { token: token, tokenSecret: tokenSecret });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      strategy.userProfile = function(token, tokenSecret, params, done) {
        done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, profile) {
          req.user = user;
          req.profile = profile;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.token, 'access-token');
        assert.equal(req.user.tokenSecret, 'access-token-secret');
      },
      'should not provide profile' : function(err, req) {
        assert.isUndefined(req.profile);
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request that fails to load user profile': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function(token, tokenSecret, info, done) {
          done(null, { token: token, tokenSecret: tokenSecret });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', {});
      }
      strategy.userProfile = function(token, tokenSecret, params, done) {
        done(new Error('something-went-wrong'));
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user, profile) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request that fails to obtain an access token': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(new Error('something-went-wrong'));
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        req.session['oauth'] = {};
        req.session['oauth']['oauth_token'] = 'token';
        req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
      'should not remove token and token secret from session' : function(err, req) {
        assert.equal(req.session['oauth']['oauth_token'], 'token');
        assert.equal(req.session['oauth']['oauth_token_secret'], 'token-secret');
      },
    },
  },
  
  'strategy handling a request to be redirected after obtaining a request token': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        callback(null, 'token', 'token-secret', {});
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        req.session = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth/authorize?oauth_token=token');
      },
      'should store token and token secret in session' : function(err, req) {
        assert.equal(req.session['oauth']['oauth_token'], 'token');
        assert.equal(req.session['oauth']['oauth_token_secret'], 'token-secret');
      },
    },
  },
  
  'strategy handling a request to be redirected to a URL with query parameters after obtaining a request token': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize?foo=bar',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        callback(null, 'token', 'token-secret', {});
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        req.session = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth/authorize?foo=bar&oauth_token=token');
      },
      'should store token and token secret in session' : function(err, req) {
        assert.equal(req.session['oauth']['oauth_token'], 'token');
        assert.equal(req.session['oauth']['oauth_token_secret'], 'token-secret');
      },
    },
  },
  
  'strategy handling a request to be redirected after obtaining a request token without extra params': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length == 0) {
          callback(null, 'token', 'token-secret', {});
        } else {
          callback(new Error('something went wrong'));
        }
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        strategy.error = function(err) {
          self.callback(err);
        }
        
        req.session = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth/authorize?oauth_token=token');
      },
      'should store token and token secret in session' : function(err, req) {
        assert.equal(req.session['oauth']['oauth_token'], 'token');
        assert.equal(req.session['oauth']['oauth_token_secret'], 'token-secret');
      },
    },
  },
  
  'strategy handling a request to be redirected after obtaining a request token with extra params': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length == 1) {
          callback(null, 'token_' + extraParams.scope, 'token-secret', {});
        } else {
          callback(new Error('something went wrong'));
        }
      }
      
      strategy.requestTokenParams = function(options) {
        return { scope: options.scope };
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        strategy.error = function(err) {
          self.callback(err);
        }
        
        req.session = {};
        process.nextTick(function () {
          strategy.authenticate(req, { scope: 'foo' });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth/authorize?oauth_token=token_foo');
      },
      'should store token and token secret in session' : function(err, req) {
        assert.equal(req.session['oauth']['oauth_token'], 'token_foo');
        assert.equal(req.session['oauth']['oauth_token_secret'], 'token-secret');
      },
    },
  },
  
  'strategy handling a request that fails to obtain a request token': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        callback(new Error('something-went-wrong'));
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        strategy.success = function(user) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.error = function(err) {
          self.callback(null, req);
        }
        
        req.session = {};
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail or redirect' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req) {
        assert.isNotNull(req);
      },
      'should not store token and token secret in session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy constructed without a verify callback': {
    'should throw an error': function (strategy) {
      assert.throws(function() {
        new OAuthStrategy({
            requestTokenURL: 'https://www.example.com/oauth/request_token',
            accessTokenURL: 'https://www.example.com/oauth/access_token',
            userAuthorizationURL: 'https://www.example.com/oauth/authorize',
            consumerKey: 'ABC123',
            consumerSecret: 'secret'
        });
      });
    },
  },
  
}).export(module);
