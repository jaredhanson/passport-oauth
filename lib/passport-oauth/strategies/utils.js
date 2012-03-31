exports.originalURL = function(req) {
  var headers = req.headers
    , protocol = (req.connection.encrypted || req.headers['x-forwarded-proto'] == 'https')
               ? 'https'
               : 'http'
    , host = headers.host
    , path = req.url || '';
  return protocol + '://' + host + path;
};
