local cjson = require "cjson"
local ngx_encode_base64 = ngx.encode_base64

local _M = {}

function _M.get_oidc_options(config)
  local oidc_opts = {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
    redirect_uri_path = config.redirect_uri_path,
    logout_path = config.logout_path,
    post_logout_redirect_uri = config.post_logout_redirect_uri,
    timeout = config.timeout,
    http_version = config.http_version,
    keepalive = config.keepalive,
    verify_nonce = config.verify_nonce,
    verify_signature = config.verify_signature,
    use_jwks = config.use_jwks,
    introspection_endpoint = config.introspection_endpoint,
    introspection_endpoint_auth_method = config.introspection_endpoint_auth_method,
    recovery_page_path = config.recovery_page_path,
    authorization_params = config.authorization_params,
    extra_jwks_uris = config.extra_jwks_uris,
  }

  if config.filters then
    oidc_opts.filters = config.filters
  end

  return oidc_opts
end

function _M.get_session_options(config)
  local session_opts = {
    secret = config.session_secret or kong.node.get_id(),
    cookie = {
      name = config.session_cookie_name,
      lifetime = config.session_cookie_lifetime,
      renew = config.session_cookie_renew,
      path = config.session_cookie_path,
      domain = config.session_cookie_domain,
      samesite = config.session_cookie_samesite,
      httponly = config.session_cookie_httponly,
      secure = config.session_cookie_secure,
    },
    storage = config.session_storage,
  }

  if config.session_storage == "memcache" then
    session_opts.memcache = {
      prefix = config.session_memcache_prefix,
      socket = config.session_memcache_socket,
    }
  elseif config.session_storage == "redis" then
    session_opts.redis = {
      prefix = config.session_redis_prefix,
      host = config.session_redis_host,
      port = config.session_redis_port,
      auth = config.session_redis_auth,
    }
  elseif config.session_storage == "shm" then
    session_opts.shm = {
      store = config.session_shm_store,
    }
  end

  return session_opts
end

function _M.set_authentication_context(user, config)
  if user.id then
    kong.client.set_credential(user)
    kong.ctx.shared.authenticated_groups = user.groups or {}
    kong.ctx.shared.authenticated_user = user
  end
end

function _M.add_headers(user, config)
  local headers = kong.service.request.get_headers()
  
  if user.access_token then
    headers[config.access_token_header_name] = ngx_encode_base64(user.access_token)
  end
  
  if user.id_token then
    headers[config.id_token_header_name] = ngx_encode_base64(user.id_token)
  end
  
  if user.user then
    headers[config.user_info_header_name] = ngx_encode_base64(cjson.encode(user.user))
  end
  
  kong.service.request.set_headers(headers)
end

function _M.handle_logout(config)
  local session = require "resty.session".open()
  if session then
    session:destroy()
  end
  
  if config.logout_redirect_uri then
    return kong.response.exit(302, nil, { Location = config.logout_redirect_uri })
  else
    return kong.response.exit(200, { message = "Logged out successfully" })
  end
end

function _M.is_logout_request(config)
  local uri = kong.request.get_path()
  return uri == config.logout_path
end

function _M.get_bearer_token()
  local authorization_header = kong.request.get_header("authorization")
  if authorization_header then
    local token = authorization_header:match("Bearer%s+(.+)")
    return token
  end
  return nil
end

function _M.introspect_access_token(config, token)
  if not config.introspection_endpoint then
    return nil, "Introspection endpoint not configured"
  end
  
  local httpc = require("resty.http").new()
  httpc:set_timeout(config.timeout)
  
  local auth_method = config.introspection_endpoint_auth_method
  local headers = {
    ["Content-Type"] = "application/x-www-form-urlencoded"
  }
  
  local body = "token=" .. token
  
  if auth_method == "client_secret_basic" then
    local auth_string = config.client_id .. ":" .. config.client_secret
    headers["Authorization"] = "Basic " .. ngx_encode_base64(auth_string)
  elseif auth_method == "client_secret_post" then
    body = body .. "&client_id=" .. config.client_id .. "&client_secret=" .. config.client_secret
  end
  
  local res, err = httpc:request_uri(config.introspection_endpoint, {
    method = "POST",
    body = body,
    headers = headers,
    ssl_verify = config.ssl_verify,
    keepalive = config.keepalive,
  })
  
  if not res then
    return nil, "Token introspection failed: " .. (err or "unknown error")
  end
  
  if res.status ~= 200 then
    return nil, "Token introspection failed with status: " .. res.status
  end
  
  local token_info = cjson.decode(res.body)
  return token_info, nil
end

return _M