local cjson = require "cjson"
local ngx_encode_base64 = ngx.encode_base64

local _M = {}

function _M.get_redirect_uri_components(config)
  local scheme = config.redirect_uri_scheme
  local host = config.redirect_uri_host
  local port = config.redirect_uri_port
  
  -- If components are explicitly configured, use them
  if scheme and host then
    return scheme, host, port or (scheme == "https" and 443 or 80)
  end
  
  -- Auto-detect load balancer scenario
  if config.auto_detect_load_balancer then
    -- Check for X-Forwarded-Proto (load balancer sets this)
    local forwarded_proto = kong.request.get_header("X-Forwarded-Proto")
    local forwarded_port = kong.request.get_header("X-Forwarded-Port")
    local forwarded_host = kong.request.get_header("X-Forwarded-Host")
    
    if forwarded_proto then
      scheme = scheme or forwarded_proto
      host = host or forwarded_host or kong.request.get_host()
      
      -- Handle port logic for load balancers
      if forwarded_port then
        port = port or tonumber(forwarded_port)
      else
        -- Load balancer scenario: assume standard ports
        port = port or (scheme == "https" and 443 or 80)
      end
      
      return scheme, host, port
    end
  end
  
  -- Fallback to Kong's detected values
  return scheme or kong.request.get_scheme(),
         host or kong.request.get_host(),
         port or kong.request.get_port()
end

function _M.get_oidc_options(config)
  local oidc_opts = {
    client_id = config.client_id,
    client_secret = config.client_secret,
    discovery = config.discovery,
    scope = config.scope,
    response_type = config.response_type,
    ssl_verify = config.ssl_verify,
    token_endpoint_auth_method = config.token_endpoint_auth_method,
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

  -- Use new redirect_uri if provided, otherwise build from redirect_uri_path
  if config.redirect_uri then
    oidc_opts.redirect_uri = config.redirect_uri
  else
    -- Build absolute redirect_uri from request headers or config overrides
    local scheme, host, port = _M.get_redirect_uri_components(config)
    local port_str = ""
    
    -- Handle port mapping logic
    if config.redirect_uri_port then
      -- If explicit port is configured, use it
      if config.redirect_uri_port ~= 443 and config.redirect_uri_port ~= 80 then
        port_str = ":" .. config.redirect_uri_port
      end
    else
      -- Use auto-detected port with standard port omission
      if (scheme == "https" and port ~= 443) or (scheme == "http" and port ~= 80) then
        port_str = ":" .. port
      end
    end
    
    oidc_opts.redirect_uri = scheme .. "://" .. host .. port_str .. config.redirect_uri_path
  end

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
  if user.access_token then
    kong.service.request.set_header(config.access_token_header_name, ngx_encode_base64(user.access_token))
  end
  
  if user.id_token then
    kong.service.request.set_header(config.id_token_header_name, ngx_encode_base64(user.id_token))
  end
  
  if user.user then
    kong.service.request.set_header(config.user_info_header_name, ngx_encode_base64(cjson.encode(user.user)))
  end
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

function _M.extract_user_groups(user_data, config)
  if not config.enable_group_authorization then
    return {}
  end
  
  local groups = {}
  
  -- Try to extract groups from configured sources
  for _, source in ipairs(config.group_claim_sources) do
    local source_groups = {}
    
    if source == "userinfo" and user_data.user then
      source_groups = _M.get_groups_from_claims(user_data.user, config)
    elseif source == "id_token" and user_data.id_token then
      if type(user_data.id_token) == "string" then
        local id_token_claims = _M.decode_jwt_payload(user_data.id_token)
        if id_token_claims then
          source_groups = _M.get_groups_from_claims(id_token_claims, config)
        end
      else
        kong.log.warn("id_token is not a string, type: " .. type(user_data.id_token))
      end
    elseif source == "access_token" and user_data.access_token then
      if type(user_data.access_token) == "string" then
        local access_token_claims = _M.decode_jwt_payload(user_data.access_token)
        if access_token_claims then
          source_groups = _M.get_groups_from_claims(access_token_claims, config)
        end
      else
        kong.log.warn("access_token is not a string, type: " .. type(user_data.access_token))
      end
    end
    
    -- Merge groups from this source
    for _, group in ipairs(source_groups) do
      if not _M.table_contains(groups, group) then
        table.insert(groups, group)
      end
    end
  end
  
  return groups
end

function _M.get_groups_from_claims(claims, config)
  if not claims then
    return {}
  end
  
  local groups = {}
  local group_claim = claims[config.group_claim_name]
  
  -- Handle nested group claims (e.g., "realm_access.roles")
  if config.group_claim_nested_key and group_claim then
    group_claim = group_claim[config.group_claim_nested_key]
  end
  
  if group_claim then
    if type(group_claim) == "table" then
      groups = group_claim
    elseif type(group_claim) == "string" then
      -- Handle comma-separated groups
      for group in string.gmatch(group_claim, "([^,]+)") do
        table.insert(groups, group:match("^%s*(.-)%s*$")) -- trim whitespace
      end
    end
  end
  
  return groups
end

function _M.decode_jwt_payload(token)
  if not token then
    return nil
  end
  
  if type(token) ~= "string" then
    kong.log.warn("Expected string token but got " .. type(token))
    return nil
  end
  
  -- Split JWT token (header.payload.signature)
  local parts = {}
  for part in string.gmatch(token, "([^.]+)") do
    table.insert(parts, part)
  end
  
  if #parts < 2 then
    return nil
  end
  
  -- Decode base64 payload
  local payload = parts[2]
  -- Add padding if needed
  local padding = 4 - (#payload % 4)
  if padding ~= 4 then
    payload = payload .. string.rep("=", padding)
  end
  
  local ok, decoded = pcall(function()
    return cjson.decode(ngx.decode_base64(payload))
  end)
  
  if ok then
    return decoded
  else
    return nil
  end
end

function _M.table_contains(table, value)
  for _, v in ipairs(table) do
    if v == value then
      return true
    end
  end
  return false
end

function _M.check_group_authorization(user_groups, config)
  if not config.enable_group_authorization then
    return true, nil
  end
  
  if not config.allowed_groups or #config.allowed_groups == 0 then
    kong.log.warn("Group authorization enabled but no allowed groups configured")
    return true, nil
  end
  
  -- Check if user has any of the allowed groups
  for _, user_group in ipairs(user_groups) do
    if _M.table_contains(config.allowed_groups, user_group) then
      kong.log.info("User authorized with group: " .. user_group)
      return true, nil
    end
  end
  
  local error_msg = config.group_authorization_error_message or "Access denied: insufficient group permissions"
  kong.log.warn("Group authorization failed. User groups: " .. table.concat(user_groups, ", ") .. 
                 ". Required groups: " .. table.concat(config.allowed_groups, ", "))
  
  return false, {
    status = config.group_authorization_error_code or 403,
    message = error_msg
  }
end

return _M