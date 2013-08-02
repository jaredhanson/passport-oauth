var chai = require('chai')
  , OAuth2Strategy = require('../../lib/strategies/oauth2')
  , util = require('util');

function MockOAuth2Strategy(options, verify) {
  OAuth2Strategy.call(this, options, verify);
}
util.inherits(MockOAuth2Strategy, OAuth2Strategy);

MockOAuth2Strategy.prototype.userProfile = function(accessToken, done) {
  if (accessToken == '2YotnFZFEjr1zCsicMWpAA') {
    return done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
  }
  return done(new Error('failed to load user profile'));
}


describe('OAuth2Strategy that overrides userProfile function', function() {
    
  describe('with default options', function() {
    
    var strategy = new MockOAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret',
        callbackURL: 'https://www.example.net/auth/example/callback',
      },
      function(accessToken, refreshToken, profile, done) {
        if (accessToken == '2YotnFZFEjr1zCsicMWpAA' && refreshToken == 'tGzv3JOkF0XG5Qx2TlKWIA') { 
          return done(null, { id: '1234', username: profile.username }, { message: 'Hello' });
        }
        return done(null, false);
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
  
    describe('handling an authorized return request', function() {
      var user
        , info;
  
      before(function(done) {
        chai.passport(strategy)
          .success(function(u, i) {
            user = u;
            info = i;
            done();
          })
          .req(function(req) {
            req.query = {};
            req.query.code = 'SplxlOBeZQQYbYS6WxSbIA';
          })
          .authenticate();
      });
  
      it('should supply user with profile', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
        expect(user.username).to.equal('jaredhanson');
      });
  
      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
    });
  });
  
});
