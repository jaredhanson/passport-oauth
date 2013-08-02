var chai = require('chai')
  , OAuth2Strategy = require('../../lib/strategies/oauth2');


describe('OAuth2Strategy with scope option', function() {
    
  var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
      scope: 'permission'
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
  
  describe('handling a request to be redirected for authorization', function() {
    var url;
  
    before(function(done) {
      chai.passport(strategy)
        .redirect(function(u) {
          url = u;
          done();
        })
        .req(function(req) {
        })
        .authenticate();
    });
  
    it('should be redirected', function() {
      expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission&client_id=ABC123&type=web_server');
    });
  });
  
});


describe('OAuth2Strategy with scope separator option', function() {
    
  var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret',
      callbackURL: 'https://www.example.net/auth/example/callback',
      scopeSeparator: ','
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
  
  describe('handling a request to be redirected for authorization with multiple scopes', function() {
    var url;
  
    before(function(done) {
      chai.passport(strategy)
        .redirect(function(u) {
          url = u;
          done();
        })
        .req(function(req) {
        })
        .authenticate({ scope: ['permission_1', 'permission_2' ] });
    });
  
    it('should be redirected', function() {
      expect(url).to.equal('https://www.example.com/oauth2/authorize?response_type=code&redirect_uri=https%3A%2F%2Fwww.example.net%2Fauth%2Fexample%2Fcallback&scope=permission_1%2Cpermission_2&client_id=ABC123&type=web_server');
    });
  });
  
});
