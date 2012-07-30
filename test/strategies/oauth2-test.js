var vows = require('vows');
var assert = require('assert');
var util = require('util');
var OAuth2Strategy = require('passport-oauth/strategies/oauth2');


vows.describe('OAuth2Strategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function() {}
      );
    },
    
    'should be named session': function (strategy) {
      assert.equal(strategy.name, 'oauth2');
    },
  },
  
  'strategy handling an authorized request': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken });
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.redirect_uri == 'https://www.example.net/auth/example/callback')  {
          callback(null, 'token', 'refresh-token');
        } else {
          callback(null, 'bad', 'really-bad');
        }
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
    },
  },
  
  'strategy handling an authorized request with params argument to callback': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
        },
        function(accessToken, refreshToken, params, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken, expiresIn: params.expires_in });
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.redirect_uri == 'https://www.example.net/auth/example/callback')  {
          callback(null, 'token', 'refresh-token', { expires_in: 3600 });
        } else {
          callback(null, 'bad', 'really-bad');
        }
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
        assert.equal(req.user.expiresIn, 3600);
      },
    },
  },
  
  'strategy handling an authorized request with req argument to callback': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          passReqToCallback: true
        },
        function(req, accessToken, refreshToken, profile, done) {
          done(null, { foo: req.foo, accessToken: accessToken, refreshToken: refreshToken });
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.redirect_uri == 'https://www.example.net/auth/example/callback')  {
          callback(null, 'token', 'refresh-token');
        } else {
          callback(null, 'bad', 'really-bad');
        }
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
      'should have request details' : function(err, req) {
        assert.equal(req.user.foo, 'bar');
      },
    },
  },
  
  'strategy handling an authorized request with req and params argument to callback': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          passReqToCallback: true
        },
        function(req, accessToken, refreshToken, params, profile, done) {
          done(null, { foo: req.foo, accessToken: accessToken, refreshToken: refreshToken, expiresIn: params.expires_in });
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.redirect_uri == 'https://www.example.net/auth/example/callback')  {
          callback(null, 'token', 'refresh-token', { expires_in: 3600 });
        } else {
          callback(null, 'bad', 'really-bad');
        }
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
        assert.equal(req.user.expiresIn, 3600);
      },
      'should have request details' : function(err, req) {
        assert.equal(req.user.foo, 'bar');
      },
    },
  },
  
  'strategy handling an authorized request with a callbackURL option override': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken });
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.redirect_uri == 'https://www.example.net/auth/example/other-callback')  {
          callback(null, 'token', 'refresh-token');
        } else {
          callback(null, 'bad', 'really-bad');
        }
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req, { callbackURL: 'https://www.example.net/auth/example/other-callback' });
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
    },
  },
  
  'strategy handling an authorized request with a relative callbackURL option override': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken });
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        if (options.redirect_uri == 'https://www.example.net/auth/example/another-callback')  {
          callback(null, 'token', 'refresh-token');
        } else {
          callback(null, 'bad', 'really-bad');
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
          req.user = user;
          self.callback(null, req);
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        
        req.query = {};
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req, { callbackURL: '/auth/example/another-callback' });
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
    },
  },
  
  'strategy handling an authorized request that is not verified': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, false);
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
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
          self.callback(null, req);
        }
        
        req.query = {};
        req.query.code = 'authorization-code'
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
    },
  },
  
  'strategy handling an authorized request that is not verified with additional info': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, false, { message: 'Invite required' });
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
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
        strategy.fail = function(info) {
          self.callback(null, req, info);
        }
        
        req.query = {};
        req.query.code = 'authorization-code'
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
    },
  },
  
  'strategy handling an authorized request that encounters an error during verification': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function(accessToken, refreshToken, profile, done) {
          done(new Error('something-went-wrong'));
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
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
          self.callback(null, req);
        }
        
        req.query = {};
        req.query.code = 'authorization-code'
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
    },
  },
  
  'strategy handling an authorized request should load user profile by default': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken }, profile);
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
      }
      strategy.userProfile = function(accessToken, done) {
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
      'should provide profile' : function(err, req, profile) {
        assert.equal(profile.location, 'Oakland, CA');
      },
    },
  },
  
  'strategy handling an authorized request should not load user profile when option is disabled': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          skipUserProfile: true
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken }, profile);
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
      }
      strategy.userProfile = function(accessToken, done) {
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
      'should not provide profile' : function(err, req, profile) {
        assert.isUndefined(profile);
      },
    },
  },
  
  'strategy handling an authorized request should load user profile when function synchronously returns false': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          skipUserProfile: function() {
            return false;
          }
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken }, profile);
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
      }
      strategy.userProfile = function(accessToken, done) {
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
      'should provide profile' : function(err, req, profile) {
        assert.equal(profile.location, 'Oakland, CA');
      },
    },
  },
  
  'strategy handling an authorized request should not load user profile when function synchronously returns true': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          skipUserProfile: function() {
            return true;
          }
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken }, profile);
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
      }
      strategy.userProfile = function(accessToken, done) {
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
      'should not provide profile' : function(err, req, profile) {
        assert.isUndefined(profile);
      },
    },
  },
  
  'strategy handling an authorized request should load user profile when function asynchronously returns false': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          skipUserProfile: function(accessToken, done) {
            done(null, false);
          }
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken }, profile);
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
      }
      strategy.userProfile = function(accessToken, done) {
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
      'should provide profile' : function(err, req, profile) {
        assert.equal(profile.location, 'Oakland, CA');
      },
    },
  },
  
  'strategy handling an authorized request should not load user profile when function asynchronously returns true': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          skipUserProfile: function(accessToken, done) {
            done(null, true);
          }
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken }, profile);
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
      }
      strategy.userProfile = function(accessToken, done) {
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
        req.query.code = 'authorization-code'
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call fail' : function(err, req) {
        assert.isNull(err);
      },
      'should authenticate' : function(err, req) {
        assert.equal(req.user.accessToken, 'token');
        assert.equal(req.user.refreshToken, 'refresh-token');
      },
      'should not provide profile' : function(err, req, profile) {
        assert.isUndefined(profile);
      },
    },
  },
  
  'strategy handling an authorized request that fails to load user profile': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken }, profile);
        }
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(null, 'token', 'refresh-token');
      }
      strategy.userProfile = function(accessToken, done) {
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
        req.query.code = 'authorization-code'
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
    },
  },
  
  'strategy handling an authorized request that fails to obtain an access token': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
      // mock
      strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
        callback(new Error('something-went-wrong'));
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
          self.callback(null, req);
        }
        
        req.query = {};
        req.query.code = 'authorization-code'
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
    },
  },
  
  'strategy handling a request to be redirected for authorization': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected to a path for authorization': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: '/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {
          connection: {},
          url: '/auth/example',
          headers: {
            'host': 'www.example.net',
          }
        };
        strategy.success = function(user) {
          req.user = user;
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=http%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling an encrypted request to be redirected to a path for authorization': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: '/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
          req.user = user;
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling an encrypted request from behind a proxy to be redirected to a path for authorization': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: '/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
      return strategy;
    },
    
    'after augmenting with actions': {
      topic: function(strategy) {
        var self = this;
        var req = {
          connection: {},
          url: '/auth/example',
          headers: {
            'host': 'www.example.net',
            'x-forwarded-proto': 'https'
          }
        };
        strategy.success = function(user) {
          req.user = user;
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with a callbackURL option override': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req, { callbackURL: 'https://www.example.net/auth/example/other-callback' });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fother-callback&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with a relative callbackURL option override': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
          req.user = user;
          self.callback(new Error('should-not-be-called'));
        }
        strategy.fail = function() {
          self.callback(new Error('should-not-be-called'));
        }
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req, { callbackURL: '/auth/example/another-callback' });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fanother-callback&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with a scope': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req, { scope: 'permission' });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with a scope specified as strategy option': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          scope: 'permission'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req);
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with state': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req, { state: 'foo123' });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&state=foo123&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with multiple scopes': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req, { scope: ['permission_1', 'permission_2' ] });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission_1%20permission_2&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with multiple scopes and scope separator option': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback',
          scopeSeparator: ','
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req, { scope: ['permission_1', 'permission_2' ] });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission_1%2Cpermission_2&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with extra params': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
      strategy.authorizationParams = function(options) {
        return { prompt: options.prompt };
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req, { prompt: 'mobile' });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?prompt=mobile&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request to be redirected for authorization with scope and extra params': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
      
      strategy.authorizationParams = function(options) {
        return { prompt: options.prompt };
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
        strategy.redirect = function(url) {
          req.redirectURL = url;
          self.callback(null, req);
        }
        
        process.nextTick(function () {
          strategy.authenticate(req, { scope: 'permission', prompt: 'mobile' });
        });
      },
      
      'should not call success or fail' : function(err, req) {
        assert.isNull(err);
      },
      'should redirect to user authorization URL' : function(err, req) {
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?prompt=mobile&response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission&client_id=ABC123&type=web_server');
      },
    },
  },
  
  'strategy handling a request that has been denied': {
    topic: function() {
      var strategy = new OAuth2Strategy({
          authorizationURL: 'https://www.example.com/oauth2/authorize',
          tokenURL: 'https://www.example.com/oauth2/token',
          clientID: 'ABC123',
          clientSecret: 'secret',
          callbackURL: 'https://www.example.net/auth/example/callback'
        },
        function(accessToken, refreshToken, profile, done) {}
      );
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
        req.query.error = 'access_denied';
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
    },
  },
  
}).export(module);
