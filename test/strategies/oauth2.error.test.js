var chai = require('chai')
  , OAuth2Strategy = require('../../lib/strategies/oauth2');


describe('OAuth2Strategy that encounters an error during verification', function() {
    
  var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
    },
    function(accessToken, refreshToken, profile, done) {
      return done(new Error('something went wrong'));
    });

  // inject a "mock" oauth2 instance
  strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
    if (code == 'SplxlOBeZQQYbYS6WxSbIA' &&
        options.grant_type == 'authorization_code' &&
        options.redirect_uri == 'https://www.example.net/auth/example/callback') {
      callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
    } else {
      callback(null, 'wrong-access-token', 'wrong-refresh-token');
    }
  }

  describe('handling a return request', function() {
    var err;

    before(function(done) {
      chai.passport(strategy)
        .error(function(e) {
          err = e;
          done();
        })
        .req(function(req) {
          req.query = {};
          req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
        })
        .authenticate();
    });

    it('should error', function() {
      expect(err).to.be.an.instanceof(Error);
      expect(err.message).to.equal('something went wrong');
    });
  });
  
});
