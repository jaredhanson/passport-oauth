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
          clientSecret: 'secret'
        },
        function(accessToken, refreshToken, profile, done) {
          done(null, { accessToken: accessToken, refreshToken: refreshToken });
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
          callbackURL: 'https://www.example.net/auth/oauth2/callback'
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
        assert.equal(req.redirectURL, 'https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Foauth2%2Fcallback&client_id=ABC123&type=web_server');
      },
    },
  },
  
}).export(module);
