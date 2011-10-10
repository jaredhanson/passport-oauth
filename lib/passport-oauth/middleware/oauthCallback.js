var parse = require('url').parse;

module.exports = function oauthCallback(url) {
  if (!url) throw new Error('oauthCallback middleware requires a URL');
  var path = parse(url).pathname;
  
  return function oauthCallback(req, res, next) {
    if (path !== parse(req.url).pathname) { return next() };
    
    if (req.query && req.query['oauth_token'] && req.query['oauth_verifier']) {
      req.auth = req.auth || {};
      req.auth.oauthToken = req.query['oauth_token'];
      req.auth.oauthVerifier = req.query['oauth_verifier'];
    }
    next();
  }
}
