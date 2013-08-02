var OAuth2Strategy = require('../../lib/strategies/oauth2');


describe('OAuth2Strategy', function() {
    
  var strategy = new OAuth2Strategy({
      authorizationURL: 'https://www.example.com/oauth2/authorize',
      tokenURL: 'https://www.example.com/oauth2/token',
      clientID: 'ABC123',
      clientSecret: 'secret'
    }, function() {});
    
  it('should be named oauth2', function() {
    expect(strategy.name).to.equal('oauth2');
  });
  
  describe('constructed without a verify callback', function() {
    expect(function() {
      new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret'
      });
    }).to.throw(TypeError, 'passport-oauth.OAuth2Strategy requires a verify callback');
  });
  
});
