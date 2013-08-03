var chai = require('chai')
  , OAuthStrategy = require('../../lib/strategies/oauth')
  , util = require('util');

function MockOAuthStrategy(options, verify) {
  OAuthStrategy.call(this, options, verify);
}
util.inherits(MockOAuthStrategy, OAuthStrategy);

MockOAuthStrategy.prototype.userAuthorizationParams = function(options) {
  return { screen_name: options.screenName };
}


describe('OAuthStrategy that overrides userAuthorizationParams function', function() {
    
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
    
    strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
      callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
    }
    
    describe('handling a request to be redirected with params', function() {
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
          .authenticate({ screenName: 'bob' });
      });

      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola&screen_name=bob');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
      });
    });
  });
  
});
