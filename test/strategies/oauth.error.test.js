var chai = require('chai')
  , OAuthStrategy = require('../../lib/strategies/oauth')
  , InternalOAuthError = require('../../lib/errors/internaloautherror');


describe('OAuthStrategy that encounters an error', function() {
    
  describe('while getting access token', function() {
    
    var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('something went wrong'));
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      callback(new Error('failed to get access token'));
    }
    
    describe('handling an authorized callback request', function() {
      var request
        , info;

      before(function(done) {
        chai.passport(strategy)
          .error(function(e) {
            err = e;
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

      it('should error', function() {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain access token');
        expect(err.oauthError.message).to.equal('failed to get access token');
      });
      
      it('should not remove token and token secret from session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    });
  });
  
  describe('while getting a request token', function() {
    
    var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('something went wrong'));
      });
    
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
      callback(new Error('failed to get request token'));
    }
    
    describe('handling an authorized callback request', function() {
      var request
        , info;

      before(function(done) {
        chai.passport(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain request token');
        expect(err.oauthError.message).to.equal('failed to get request token');
      });
      
      it('should not store token and token secret in session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
  });
    
  describe('while verifying user profile', function() {
    
    var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('something went wrong'));
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
        , info;

      before(function(done) {
        chai.passport(strategy)
          .error(function(e) {
            err = e;
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

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('something went wrong');
      });
      
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    });
  });
  
});
