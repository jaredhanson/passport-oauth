var chai = require('chai')
  , OAuthStrategy = require('../../lib/strategies/oauth');


describe('OAuthStrategy that accepts params in verify callback', function() {
    
  var strategy = new OAuthStrategy({
      requestTokenURL: 'https://www.example.com/oauth/request_token',
      accessTokenURL: 'https://www.example.com/oauth/access_token',
      userAuthorizationURL: 'https://www.example.com/oauth/authorize',
      consumerKey: 'ABC123',
      consumerSecret: 'secret'
    }, function(token, tokenSecret, params, profile, done) {
      if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00' && params.elephant == 'purple' && Object.keys(profile).length == 0) {
        return done(null, { id: '1234' }, { message: 'Hello' });
      }
      return done(null, false);
    });
    
  // inject a "mock" oauth instance
  strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
    if (token == 'hh5s93j4hdidpola' && tokenSecret == 'hdhd0244k9j7ao03' && verifier == 'hfdp7dh39dks9884') {
      return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', { elephant: 'purple' });
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
  
});
