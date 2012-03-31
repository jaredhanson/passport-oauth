var vows = require('vows');
var assert = require('assert');
var util = require('util');
var InternalOAuthError = require('passport-oauth/errors/internaloautherror');


vows.describe('InternalOAuthError').addBatch({
  
  'when constructed with only a message': {
    topic: function() {
      return new InternalOAuthError('oops');
    },
    
    'should format message properly': function (err) {
      assert.equal(err.toString(), 'oops');
    },
  },
  
  'when constructed with a message and error': {
    topic: function() {
      return new InternalOAuthError('oops', new Error('something is wrong'));
    },
    
    'should format message properly': function (err) {
      assert.equal(err.toString(), 'oops (Error: something is wrong)');
    },
  },
  
  'when constructed with a message and object with status code and data': {
    topic: function() {
      return new InternalOAuthError('oops', { statusCode: 401, data: 'invalid OAuth credentials' });
    },
    
    'should format message properly': function (err) {
      assert.equal(err.toString(), 'oops (status: 401 data: invalid OAuth credentials)');
    },
  },
  
}).export(module);
