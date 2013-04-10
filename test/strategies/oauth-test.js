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
  
  'strategy without custom headers': {
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
      assert.lengthOf(Object.keys(strategy._oauth._headers), 3);
      assert.equal(strategy._oauth._headers['User-Agent'], 'Node authentication');
    },
  },
  
  'strategy with custom headers': {
    topic: function() {
      return new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          customHeaders: { 'X-FOO': 'bar' }
        },
        function() {}
      );
    },
    
    'should be named session': function (strategy) {
      assert.lengthOf(Object.keys(strategy._oauth._headers), 1);
      assert.equal(strategy._oauth._headers['X-FOO'], 'bar');
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
        function(token, tokenSecret, profile, done) {
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
  
  'strategy handling an authorized request with params argument to callback': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function(token, tokenSecret, params, profile, done) {
          done(null, { token: token, tokenSecret: tokenSecret, color: params.elephant });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', { elephant: 'purple' });
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
        assert.equal(req.user.color, 'purple');
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request with req argument to callback': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          passReqToCallback: true
        },
        function(req, token, tokenSecret, profile, done) {
          done(null, { foo: req.foo, token: token, tokenSecret: tokenSecret });
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
        req.foo = 'bar';
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
      'should have request details' : function(err, req) {
        assert.equal(req.user.foo, 'bar');
      },
      'should remove token and token secret from session' : function(err, req) {
        assert.isUndefined(req.session['oauth']);
      },
    },
  },
  
  'strategy handling an authorized request with req and params argument to callback': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          passReqToCallback: true
        },
        function(req, token, tokenSecret, params, profile, done) {
          done(null, { foo: req.foo, token: token, tokenSecret: tokenSecret, color: params.elephant });
        }
      );
      
      // mock
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        callback(null, 'access-token', 'access-token-secret', { elephant: 'purple' });
      }
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {};
        req.foo = 'bar';
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
        assert.equal(req.user.color, 'purple');
      },
      'should have request details' : function(err, req) {
        assert.equal(req.user.foo, 'bar');
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
        function(token, tokenSecret, profile, done) {
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
  
  'strategy handling an authorized request that is not verified with additional info': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function(token, tokenSecret, profile, done) {
          done(null, false, { message: 'Invite required' });
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
        strategy.fail = function(info) {
          self.callback(null, req, info);
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
      'should pass additional info' : function(err, req, info) {
        assert.equal(info.message, 'Invite required');
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
        function(token, tokenSecret, profile, done) {
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
        function(token, tokenSecret, profile, done) {
          done(null, { token: token, tokenSecret: tokenSecret }, profile);
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
        strategy.success = function(user, info) {
          req.user = user;
          self.callback(null, req, info);
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
      'should provide profile' : function(err, req, profile) {
        assert.equal(profile.location, 'Oakland, CA');
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
        function(token, tokenSecret, profile, done) {
          done(null, { token: token, tokenSecret: tokenSecret }, profile);
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
        strategy.success = function(user, info) {
          req.user = user;
          self.callback(null, req, info);
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
      'should not provide profile' : function(err, req, profile) {
        assert.isUndefined(profile);
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
        function(token, tokenSecret, profile, done) {
          done(null, { token: token, tokenSecret: tokenSecret }, profile);
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
        strategy.success = function(user, info) {
          req.user = user;
          self.callback(null, req, info);
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
      'should provide profile' : function(err, req, profile) {
        assert.equal(profile.location, 'Oakland, CA');
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
        function(token, tokenSecret, profile, done) {
          done(null, { token: token, tokenSecret: tokenSecret }, profile);
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
        strategy.success = function(user, info) {
          req.user = user;
          self.callback(null, req, info);
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
      'should not provide profile' : function(err, req, profile) {
        assert.isUndefined(profile);
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
        function(token, tokenSecret, profile, done) {
          done(null, { token: token, tokenSecret: tokenSecret }, profile);
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
        strategy.success = function(user, info) {
          req.user = user;
          self.callback(null, req, info);
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
      'should provide profile' : function(err, req, profile) {
        assert.equal(profile.location, 'Oakland, CA');
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
        function(token, tokenSecret, profile, done) {
          done(null, { token: token, tokenSecret: tokenSecret }, profile);
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
        strategy.success = function(user, info) {
          req.user = user;
          self.callback(null, req, info);
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
      'should not provide profile' : function(err, req, profile) {
        assert.isUndefined(profile);
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
        function(token, tokenSecret, profile, done) {
          done(null, { token: token, tokenSecret: tokenSecret }, profile);
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
        strategy.success = function(user, info) {
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
  
  'strategy handling an authorized request that lacks request token in session': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function(token, tokenSecret, profile, done) {
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
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.error = function(err) {
          self.callback(null, req, err);
        }
        
        req.query = {};
        req.query['oauth_token'] = 'token';
        req.session = {};
        //req.session['oauth'] = {};
        //req.session['oauth']['oauth_token'] = 'token';
        //req.session['oauth']['oauth_token_secret'] = 'token-secret';
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should call error' : function(err, req, e) {
        assert.isNotNull(req);
        assert.instanceOf(e, Error);
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
  
  'strategy handling a request to be redirected with authorization params after obtaining a request token': {
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
      
      strategy.userAuthorizationParams = function(options) {
        return { screen_name: options.screenName };
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
          strategy.authenticate(req, { screenName: 'bob' });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth/authorize?oauth_token=token&screen_name=bob');
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
        delete extraParams.oauth_callback
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
        delete extraParams.oauth_callback
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
  
  'strategy handling a request to be redirected after obtaining a request token using default callback URL': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          callbackURL: 'https://www.example.net/auth/example/callback',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (extraParams.oauth_callback == 'https://www.example.net/auth/example/callback') {
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
  
  'strategy handling a request to be redirected after obtaining a request token using default relative callback URL': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          callbackURL: '/auth/example/cb',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (extraParams.oauth_callback == 'https://www.example.net/auth/example/cb') {
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
        var req = {
          connection: { encrypted: true },
          url: '/auth/example',
          headers: {
            'host': 'www.example.net',
          }
        };
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
  
  'strategy handling a request to be redirected after obtaining a request token using override callback URL': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          callbackURL: 'https://www.example.net/auth/example/callback',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (extraParams.oauth_callback == 'https://www.example.net/auth/example/other-callback') {
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
          strategy.authenticate(req, { callbackURL: 'https://www.example.net/auth/example/other-callback' });
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
  
  'strategy handling a request to be redirected after obtaining a request token using relative override callback URL': {
    topic: function() {
      var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          callbackURL: 'https://www.example.net/auth/example/callback',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        },
        function() {}
      );
      
      // mock
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (extraParams.oauth_callback == 'https://www.example.net/auth/example/another-callback') {
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
        var req = {
          connection: { encrypted: true },
          url: '/auth/example',
          headers: {
            'host': 'www.example.net',
          }
        };
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
          strategy.authenticate(req, { callbackURL: '/auth/example/another-callback' });
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
  
  'strategy constructed without a consumerSecret': {
    'should throw an error': function (strategy) {
      assert.throws(function() {
        new OAuthStrategy({
            requestTokenURL: 'https://www.example.com/oauth/request_token',
            accessTokenURL: 'https://www.example.com/oauth/access_token',
            userAuthorizationURL: 'https://www.example.com/oauth/authorize',
            consumerKey: 'ABC123'
        }, function() {});
      });
    },
  },
  
  'strategy constructed with an empty consumerSecret': {
    'should throw an error': function (strategy) {
      assert.doesNotThrow(function() {
        new OAuthStrategy({
            requestTokenURL: 'https://www.example.com/oauth/request_token',
            accessTokenURL: 'https://www.example.com/oauth/access_token',
            userAuthorizationURL: 'https://www.example.com/oauth/authorize',
            consumerKey: 'ABC123',
            consumerSecret: ''
        }, function() {});
      });
    },
  },
  
}).export(module);
