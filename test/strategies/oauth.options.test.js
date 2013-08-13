var chai = require('chai')
  , OAuthStrategy = require('../../lib/strategies/oauth')
  , util = require('util');

describe('OAuthStrategy', function() {
    
  describe('with callback URL option', function() {
    var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback'
      }, function(token, tokenSecret, profile, done) {
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
        } else if (token == 'nnch734d00sl2jdk+alt1' && tokenSecret == 'pfkkdhi9sl3r4s00+alt1') {
          return done(null, { id: '2234', profile: profile }, { message: 'Hello' });
        } else if (token == 'nnch734d00sl2jdk-alt1' && tokenSecret == 'pfkkdhi9sl3r4s00-alt1') {
          return done(null, { id: '3234', profile: profile }, { message: 'Hello' });
        }
        return done(null, false);
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      if (token == 'hh5s93j4hdidpola' && tokenSecret == 'hdhd0244k9j7ao03' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      } else if (token == 'hh5s93j4hdidpola+alt1' && tokenSecret == 'hdhd0244k9j7ao03+alt1' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk+alt1', 'pfkkdhi9sl3r4s00+alt1', {});
      } else if (token == 'hh5s93j4hdidpola-alt2' && tokenSecret == 'hdhd0244k9j7ao03-alt2' && verifier == 'hfdp7dh39dks9884') {
        return callback(null, 'nnch734d00sl2jdk-alt2', 'pfkkdhi9sl3r4s00-alt2', {});
      } else {
        return callback(null, 'wrong-token', 'wrong-token-secret');
      }
    }
    
    strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
      if (extraParams.oauth_callback == 'https://www.example.net/auth/example/callback') {
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
      } else if (extraParams.oauth_callback == 'https://www.example.net/auth/example/callback/alt1') {
        callback(null, 'hh5s93j4hdidpola+alt1', 'hdhd0244k9j7ao03+alt1', {});
      } else if (extraParams.oauth_callback == 'https://www.example.net/auth/example/callback/alt2') {
        callback(null, 'hh5s93j4hdidpola-alt2', 'hdhd0244k9j7ao03-alt2', {});
      } else {
        callback(new Error('wrong request token params'));
      }
    }
    
    describe('handling a request to be redirected', function() {
      var request
        , url;

      before(function(done) {
        chai.passport(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });

      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    });
    
    describe('handling a request to be redirected with callback URL option override', function() {
      var request
        , url;

      before(function(done) {
        chai.passport(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate({ callbackURL: 'https://www.example.net/auth/example/callback/alt1' });
      });

      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola%2Balt1');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola+alt1');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03+alt1');
      });
    });
    
    describe('handling a request to be redirected with relative callback URL option override', function() {
      var request
        , url;

      before(function(done) {
        chai.passport(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.url = '/auth/example'
            req.headers.host = 'www.example.net';
            req.session = {};
            req.connection = { encrypted: true };
          })
          .authenticate({ callbackURL: '/auth/example/callback/alt2' });
      });

      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola-alt2');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola-alt2');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03-alt2');
      });
    });
  });
  
  describe('with relative callback URL option', function() {
    var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        callbackURL: '/auth/example/cb'
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
    
    strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
      if (extraParams.oauth_callback == 'https://www.example.net/auth/example/cb') {
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
      } else {
        callback(new Error('wrong request token params'));
      }
    }
    
    describe('handling a request to be redirected for authorization', function() {
      var request
        , url;

      before(function(done) {
        chai.passport(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.url = '/auth/example'
            req.headers.host = 'www.example.net';
            req.session = {};
            req.connection = { encrypted: true };
          })
          .authenticate({ scope: 'foo' });
      });

      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    });
  });
  
  describe('with user authorization URL that contains query parameters', function() {
    var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize?foo=bar',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        if (Object.keys(profile).length !== 0) { return done(null, false); }
        
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234' }, { message: 'Hello' });
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
  
    strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
      callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
    }
  
    describe('handling a request to be redirected after obtaining a request token', function() {
      var request
        , url;

      before(function(done) {
        chai.passport(strategy)
          .redirect(function(u) {
            url = u;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });

      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?foo=bar&oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    });
  });
  
});
