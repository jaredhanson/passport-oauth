var chai = require('chai')
  , OAuthStrategy = require('../../lib/strategies/oauth')
  , util = require('util');

function MockOAuthStrategy(options, verify) {
  OAuthStrategy.call(this, options, verify);
}
util.inherits(MockOAuthStrategy, OAuthStrategy);

MockOAuthStrategy.prototype.userProfile = function(token, tokenSecret, params, done) {
  if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
    return done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
  }
  return done(new Error('failed to load user profile'));
}


describe('OAuthStrategy that overrides userProfile function', function() {
    
  describe('with default options', function() {
    
    var strategy = new MockOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
        }
        return done(null, false);
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      if (token == 'hh5s93j4hdidpola' && tokenSecret == 'hdhd0244k9j7ao03' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      } else {
        return callback(null, 'wrong-token', 'wrong-token-secret');
      }
    }
    
    describe('handling an authorized callback request', function() {
      var request
        , user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should supply user with profile', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
        expect(user.profile).to.not.be.undefined;
        expect(user.profile.username).to.equal('jaredhanson');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
    
    describe('failing to load user profile', function() {
      var request
        , err;

      before(function(done) {
        chai.passport(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'wrong-token';
            req.query['oauth_verifier'] = 'wrong-verifier';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'wrong-token';
            req.session['oauth']['oauth_token_secret'] = 'wrong-token-secret';
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error)
        expect(err.message).to.equal('failed to load user profile');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
  });
  
  describe('with skip profile option set to true', function() {
    
    var strategy = new MockOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: true
      }, function(token, tokenSecret, profile, done) {
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
        }
        return done(null, false);
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      if (token == 'hh5s93j4hdidpola' && tokenSecret == 'hdhd0244k9j7ao03' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      } else {
        return callback(null, 'wrong-token', 'wrong-token-secret');
      }
    }
    
    describe('handling an authorized callback request', function() {
      var request
        , user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should supply user without profile', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
        expect(user.profile).to.be.undefined;
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
  });
  
  describe('with skip profile function that sync returns false', function() {
    
    var strategy = new MockOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: function() {
          return false;
        }
      }, function(token, tokenSecret, profile, done) {
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
        }
        return done(null, false);
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      if (token == 'hh5s93j4hdidpola' && tokenSecret == 'hdhd0244k9j7ao03' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      } else {
        return callback(null, 'wrong-token', 'wrong-token-secret');
      }
    }
    
    describe('handling an authorized callback request', function() {
      var request
        , user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should supply user with profile', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
        expect(user.profile).to.not.be.undefined;
        expect(user.profile.username).to.equal('jaredhanson');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
  });
  
  describe('with skip profile function that sync returns true', function() {
    
    var strategy = new MockOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: function() {
          return true;
        }
      }, function(token, tokenSecret, profile, done) {
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
        }
        return done(null, false);
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      if (token == 'hh5s93j4hdidpola' && tokenSecret == 'hdhd0244k9j7ao03' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      } else {
        return callback(null, 'wrong-token', 'wrong-token-secret');
      }
    }
    
    describe('handling an authorized callback request', function() {
      var request
        , user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should supply user without profile', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
        expect(user.profile).to.be.undefined;
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
  });
  
  describe('with skip profile function that async returns false', function() {
    
    var strategy = new MockOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: function(token, tokenSecret, done) {
          if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') { return done(null, false); }
          return done(null, true);
        }
      }, function(token, tokenSecret, profile, done) {
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
        }
        return done(null, false);
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      if (token == 'hh5s93j4hdidpola' && tokenSecret == 'hdhd0244k9j7ao03' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      } else {
        return callback(null, 'wrong-token', 'wrong-token-secret');
      }
    }
    
    describe('handling an authorized callback request', function() {
      var request
        , user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should supply user with profile', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
        expect(user.profile).to.not.be.undefined;
        expect(user.profile.username).to.equal('jaredhanson');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
  });
  
  describe('with skip profile function that async returns true', function() {
    
    var strategy = new MockOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: function(token, tokenSecret, done) {
          if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') { return done(null, true); }
          return done(null, false);
        }
      }, function(token, tokenSecret, profile, done) {
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
        }
        return done(null, false);
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      if (token == 'hh5s93j4hdidpola' && tokenSecret == 'hdhd0244k9j7ao03' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      } else {
        return callback(null, 'wrong-token', 'wrong-token-secret');
      }
    }
    
    describe('handling an authorized callback request', function() {
      var request
        , user
        , info;

      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            request = req;
            req.query = {};
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });

      it('should supply user without profile', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
        expect(user.profile).to.be.undefined;
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
  });
  
});
