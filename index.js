/*
 * decaffeinate suggestions:
 * DS102: Remove unnecessary code created because of implicit returns
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const request = require('request');
const qs = require('querystring');
const NodeCache = require('node-cache');

// must be lower than response.expires_in !!
const AUTH0_TOKEN_TIMEOUT_SEC= 23 * 60 * 60; // hours * min * sec

const nodeCache = new NodeCache({stdTTL: AUTH0_TOKEN_TIMEOUT_SEC , checkperiod: 120});

const downloadToken = function(clientID , clientSecret, domain, cb) {
  const token_endpoint = '/oauth/token';

  console.log(`auth0.clientID == ${clientID}`);

  const options = { 
    method:'POST',
    url: `https://${domain}${token_endpoint}`,
    headers: { 
      'content-type': 'application/json'
    }, 
    body: { 
      grant_type: 'client_credentials',
      client_id: clientID,
      client_secret: clientSecret,
      audience: `https://${domain}/api/v2/`
    }, 
    json: true 
  };
  
  return request(options, function(error, response, body) { 
    console.log("--> auth0-oath Resp-status:", response != null ? response.statusCode : undefined);  
    if (error || body.error) {
      return cb((error || (new Error(body.error))));
    } else {
      console.log("--> auth0-oath TOKEN expires in:", response.body.expires_in);
      return cb(null, body);
    }
  });
};


// cb = ( err, httpTOKEN ) ->        
module.exports = function(clientID , clientSecret, domain, cb) {

  let t;
  const key = `auth0-token-${domain}`;
  
  console.log("--> AUTH0-Token cache-checking, key:", key);

  // guard 1
  if (!clientID) {
    cb((new Error("!! clientID unset!!")));
    return;
  }

  // guard 2
  if (!clientSecret) {
    cb((new Error("!! clientSecret unset!!")));
    return;
  }

  // guard 3
  if (!domain) {
    cb((new Error("!! domain unset!!")));
    return;
  }


  try {
    t = nodeCache.get(key, true);
    console.log(" \\ valid oauth TOKEN in cache!");
    return cb(null, t);

  } catch (nodeCacheError) {

    console.log(" \\ NO valid oauth TOKEN in cache !");

    return downloadToken(clientID , clientSecret, domain, function(err, response) {
      if (err) { 
        return cb(err);
      } else { 
        t = response.token_type+" "+response.access_token;
        nodeCache.set(key, t);
        console.log(" \\-- oauth TOKEN stored into cache!");
        return cb(null, t);
      }
    }); 
  }
};
