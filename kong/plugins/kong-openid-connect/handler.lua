local BasePlugin = require "kong.plugins.base_plugin"
local utils = require "kong.plugins.kong-openid-connect.utils"

local OpenIdConnectHandler = BasePlugin:extend()

OpenIdConnectHandler.PRIORITY = 1000
OpenIdConnectHandler.VERSION = "1.0.0"

function OpenIdConnectHandler:new()
  OpenIdConnectHandler.super.new(self, "kong-openid-connect")
end

function OpenIdConnectHandler:access(config)
  OpenIdConnectHandler.super.access(self)
  
  if utils.is_logout_request(config) then
    return utils.handle_logout(config)
  end
  
  if config.bearer_only then
    local token = utils.get_bearer_token()
    if token then
      if config.introspection_endpoint then
        local token_info, err = utils.introspect_access_token(config, token)
        if err or not token_info or not token_info.active then
          kong.log.err("Token introspection failed: " .. (err or "token inactive"))
          return kong.response.exit(401, { message = "Unauthorized" })
        end
        utils.set_authentication_context({ user = token_info }, config)
        return
      else
        kong.log.warn("Bearer token provided but no introspection endpoint configured")
      end
    else
      kong.log.err("Bearer only mode enabled but no Authorization header found")
      return kong.response.exit(401, { message = "Unauthorized" })
    end
  end
  
  local oidc = require "resty.openidc"
  
  if not oidc then
    kong.log.err("lua-resty-openidc module not found")
    return kong.response.exit(500, { message = "Internal server error" })
  end

  local session_opts = utils.get_session_options(config)
  local oidc_opts = utils.get_oidc_options(config)
  
  local res, err = oidc.authenticate(oidc_opts, config.redirect_uri_path, nil, session_opts)
  
  if err then
    if config.bearer_only then
      kong.log.err("OIDC authentication failed: " .. err)
      return kong.response.exit(401, { message = "Unauthorized" })
    end
    kong.log.err("OIDC authentication error: " .. err)
    return kong.response.exit(500, { message = "Internal server error" })
  end

  if res then
    utils.set_authentication_context(res, config)
    utils.add_headers(res, config)
  end
end

function OpenIdConnectHandler:header_filter(config)
  OpenIdConnectHandler.super.header_filter(self)
end

function OpenIdConnectHandler:body_filter(config)
  OpenIdConnectHandler.super.body_filter(self)
end

function OpenIdConnectHandler:log(config)
  OpenIdConnectHandler.super.log(self)
end

return OpenIdConnectHandler