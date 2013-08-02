var chai = require('chai')
  , OAuth2Strategy = require('../../lib/strategies/oauth2');


describe('OAuth2Strategy with explicity per-request state', function() {
    
  var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback'
    },
    function(accessToken, refreshToken, profile, done) {
      if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
        return done(null, { id: '1234' }, { message: 'Hello' });
      }
      return done(null, false);
    });
  
  // inject a "mock" oauth2 instance
  strategy._oauth2.getOAuthAccessToken = function(code, options, callback) {
    if (code == 'SplxlOBeZQQYbYS6WxSbIA' && options.grant_type == 'authorization_code' &&
        options.redirect_uri == 'https://www.example.net/auth/example/callback') {
      callback(null, '2YotnFZFEjr1zCsicMWpAA', 'tGzv3JOkF0XG5Qx2TlKWIA', { token_type: 'example', expires_in: 3600, example_parameter: 'example_value' });
    } else {
      callback(null, 'wrong-access-token', 'wrong-refresh-token');
    }
  }
  
  describe('handling a request to be redirected for authorization with explicit state', function() {
    var url;
  
    before(function(done) {
      chai.passport(strategy)
        .redirect(function(u) {
          url = u;
          done();
        })
        .req(function(req) {
        })
        .authenticate({ state: 'foo123' });
    });
  
    it('should be redirected', function() {
      expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&state=foo123&client_id=ABC123&type=web_server');
    });
  });
  
});
