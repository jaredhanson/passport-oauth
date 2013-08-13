var InternalOAuthError = require('../../lib/errors/internaloautherror');


describe('InternalOAuthError', function() {
    
  describe('constructed with a message', function() {
    var err = new InternalOAuthError('oops');
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('oops');
    });
  });
  
  describe('constructed with a message and error', function() {
    var err = new InternalOAuthError('oops', new Error('something is wrong'));
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('oops (Error: something is wrong)');
    });
  });
  
  describe('constructed with a message and object with status code and data', function() {
    var err = new InternalOAuthError('oops', { statusCode: 401, data: 'invalid OAuth credentials' });
    
    it('should format correctly', function() {
      expect(err.toString()).to.equal('oops (status: 401 data: invalid OAuth credentials)');
    });
  });
  
});
