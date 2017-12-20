request = require 'request'
qs = require 'querystring'
NodeCache = require 'node-cache'

# must be lower than response.expires_in !!
AUTH0_TOKEN_TIMEOUT_SEC= 23 * 60 * 60 # hours * min * sec

nodeCache = new NodeCache {stdTTL: AUTH0_TOKEN_TIMEOUT_SEC , checkperiod: 120}

downloadToken = (config, cb) ->
  token_endpoint = '/oauth/token'
  domain = config.domain
  clientID = config.clientID
  clientSecret = config.clientSecret

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

module.exports = (req, res, next) ->

  key = "auth0-token-#{req.headers['host']}"
  
  console.log "--> AUTH0-Token cache-checking, key:", key

  if req.headers['x-ds-auth0']
    auth0Config = JSON.parse (decodeURIComponent req.headers['x-ds-auth0'])
  else if process.env.AUTH0_CONFIG
    console.warn "-!-> Auth0 config from evironment AUTH0_CONFIG !!"
    auth0Config = qs.parse process.env.AUTH0_CONFIG
  else
    return next (new Error "AUTH0 config err; x-ds-auth0 header/ AUTH0_CONFIG env missing !")

  # deliver down to rest of chain
  req.auth0 = auth0Config

  # guard 1
  unless auth0Config.clientID
    next (new Error "!! .clientID unset!!")
    return

  # guard 2
  unless auth0Config.clientSecret
    next (new Error "!! .clientSecret unset!!")
    return

  # guard 3
  unless auth0Config.domain
    next (new Error "!! .domain unset!!")
    return


  try
    token = nodeCache.get key, true
    # deliver down to rest of chain
    req.auth0.token = token
    console.log " \\ valid oauth TOKEN!"
    next()

  catch nodeCacheError

    console.log " \\ NO valid oauth TOKEN in cache !"

    downloadToken auth0Config, (err, response) ->
      if err 
        next err
      else 
        tokenHTTPHeader = response.token_type+" "+response.access_token
        # deliver down to rest of chain
        req.auth0.token = tokenHTTPHeader
        newToken = nodeCache.set key, tokenHTTPHeader
        console.log " \\-- oauth TOKEN set in cache!"
        next()
