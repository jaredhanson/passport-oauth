var strategy = require('..');

describe('passport-oauth', function() {
  
  it('should export Strategy constructors', function() {
    expect(strategy.OAuthStrategy).to.be.a('function');
    expect(strategy.OAuth2Strategy).to.be.a('function');
  });
  
  it('should export Error constructors', function() {
    expect(strategy.InternalOAuthError).to.be.a('function');
  });
  
});
