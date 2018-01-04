request = require 'request'
qs = require 'querystring'
NodeCache = require 'node-cache'

# must be lower than response.expires_in !!
AUTH0_TOKEN_TIMEOUT_SEC= 23 * 60 * 60 # hours * min * sec

nodeCache = new NodeCache {stdTTL: AUTH0_TOKEN_TIMEOUT_SEC , checkperiod: 120}

downloadToken = (clientID , clientSecret, domain, cb) ->
  token_endpoint = '/oauth/token'

  console.log "auth0.clientID == #{clientID}"

  options = 
    method:'POST',
    url: "https://#{domain}#{token_endpoint}",
    headers: 
      'content-type': 'application/json' ,
    body: 
      grant_type: 'client_credentials',
      client_id: clientID,
      client_secret: clientSecret,
      audience: "https://#{domain}/api/v2/" ,
    json: true 
  
  request options, (error, response, body) -> 
    console.log "--> auth0-oath Resp-status:", response?.statusCode  
    if error or body.error
      cb (error or (new Error body.error))
    else
      console.log "--> auth0-oath TOKEN expires in:", response.body.expires_in
      cb null, body


# cb = ( err, httpTOKEN ) ->        
module.exports = (clientID , clientSecret, domain, cb) ->

  key = "auth0-token-#{domain}"
  
  console.log "--> AUTH0-Token cache-checking, key:", key

  # guard 1
  unless clientID
    cb (new Error "!! clientID unset!!")
    return

  # guard 2
  unless clientSecret
    cb (new Error "!! clientSecret unset!!")
    return

  # guard 3
  unless domain
    cb (new Error "!! domain unset!!")
    return


  try
    t = nodeCache.get key, true
    console.log " \\ valid oauth TOKEN in cache!"
    cb null, t

  catch nodeCacheError

    console.log " \\ NO valid oauth TOKEN in cache !"

    downloadToken clientID , clientSecret, domain, (err, response) ->
      if err 
        cb err
      else 
        t = response.token_type+" "+response.access_token
        nodeCache.set key, t
        console.log " \\-- oauth TOKEN stored into cache!"
        cb null, t 
