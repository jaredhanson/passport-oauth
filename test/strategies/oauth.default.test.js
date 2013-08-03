var chai = require('chai')
  , OAuthStrategy = require('../../lib/strategies/oauth');


describe('OAuthStrategy with default options', function() {
    
  var strategy = new OAuthStrategy({
      requestTokenURL: 'https://www.example.com/oauth/request_token',
      accessTokenURL: 'https://www.example.com/oauth/access_token',
      userAuthorizationURL: 'https://www.example.com/oauth/authorize',
      consumerKey: 'ABC123',
      consumerSecret: 'secret'
    }, function(token, tokenSecret, profile, done) {
      if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00' && Object.keys(profile).length == 0) {
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

    it('should supply user', function() {
      expect(user).to.be.an.object;
      expect(user.id).to.equal('1234');
    });

    it('should supply info', function() {
      expect(info).to.be.an.object;
      expect(info.message).to.equal('Hello');
    });
    
    it('should remove token and token secret from session', function() {
      expect(request.session['oauth']).to.be.undefined;
    });
  });
  
  describe('handling an authorized callback request that lacks request token in session', function() {
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
          req.query['oauth_token'] = 'hh5s93j4hdidpola';
          req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
          req.session = {};
        })
        .authenticate();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceof(Error);
      expect(err.message).to.equal('Failed to find request token in session');
    });
    
    it('should still lack token and token secret from session', function() {
      expect(request.session['oauth']).to.be.undefined;
    });
  });
  
  describe('handling an request to be redirected after obtaining a request token', function() {
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
  
});


describe('OAuthStrategy with default options and URL with query parameters', function() {
    
  var strategy = new OAuthStrategy({
      requestTokenURL: 'https://www.example.com/oauth/request_token',
      accessTokenURL: 'https://www.example.com/oauth/access_token',
      userAuthorizationURL: 'https://www.example.com/oauth/authorize?foo=bar',
      consumerKey: 'ABC123',
      consumerSecret: 'secret'
    }, function(token, tokenSecret, profile, done) {
      if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00' && Object.keys(profile).length == 0) {
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
  
  describe('handling an request to be redirected after obtaining a request token', function() {
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
