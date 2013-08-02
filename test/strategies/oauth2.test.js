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
    }).to.throw(TypeError, 'OAuth2Strategy requires a verify callback');
  });
  
  describe('constructed without a authorizationURL option', function() {
    expect(function() {
      new OAuth2Strategy({
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123',
        clientSecret: 'secret'
      }, function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a authorizationURL option');
  });
  
  describe('constructed without a tokenURL option', function() {
    expect(function() {
      new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        clientID: 'ABC123',
        clientSecret: 'secret'
      }, function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a tokenURL option');
  });
  
  describe('constructed without a clientID option', function() {
    expect(function() {
      new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientSecret: 'secret'
      }, function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a clientID option');
  });
  
  describe('constructed without a clientSecret option', function() {
    expect(function() {
      new OAuth2Strategy({
        authorizationURL: 'https://www.example.com/oauth2/authorize',
        tokenURL: 'https://www.example.com/oauth2/token',
        clientID: 'ABC123'
      }, function() {});
    }).to.throw(TypeError, 'OAuth2Strategy requires a clientSecret option');
  });
  
});
