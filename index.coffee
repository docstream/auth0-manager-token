request = require 'request'
qs = require 'querystring'

# must be lower than response.expires_in !!
AUTH0_TOKEN_TIMEOUT_SEC= 23 * 60 * 60 # hours * min * sec

nodeCache = new (require 'node-cache' ) {stdTTL: AUTH0_TOKEN_TIMEOUT_SEC , checkperiod: 120}

downloadToken = (config, cb) ->
  TOKEN_ENDPOINT='/oauth/token'

  unless config.clientID and config.clientSecret
    cb (new Error "Both clientID+clientSecret must be set !!!!")
    return

  console.log "auth0.clientID == #{config.clientID}"

  options = 
    method:'POST',
    url: "https://#{config.domain}#{TOKEN_ENDPOINT}",
    headers: 
      'content-type': 'application/json' ,
    body: 
      grant_type: 'client_credentials',
      client_id: config.clientID,
      client_secret: config.clientSecret,
      audience: "https://#{config.domain}/api/v2/" ,
    json: true 
  
  request options, (error, response, body) -> 
    console.log "--> auth0-oath Resp-status:", response?.statusCode  
    if error or body.error
      cb (error or (new Error body.error))
    else
      console.log "--> auth0-oath TOKEN expires in:", response.body.expires_in
      cb null, body

module.exports = (req, res, next) ->

  key = "auth0-token-#{req.wrkspc}"
  
  console.log "AUTH0-Token cache-checking, key:", key

  if req.headers['x-ds-auth0']
    auth0Config = JSON.parse (decodeURIComponent req.headers['x-ds-auth0'])
  else if process.env.AUTH0_CONFIG
    console.warn "AUTH0 config from evironment !!"
    auth0Config = qs.parse process.env.AUTH0_CONFIG
  else
    return next (new Error "AUTH0 config err; x-ds-auth0 header/ AUTH0_CONFIG env missing !")

  req.auth0 = auth0Config

  try
    token = nodeCache.get key, true

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
        req.auth0.token = tokenHTTPHeader
        newToken = nodeCache.set key, tokenHTTPHeader
        console.log " \\-- oauth TOKEN set in cache!"
        next()
