package = "kong-openid-connect"
version = "1.0.0-1"

local pluginName = "kong-openid-connect"

supported_platforms = {"linux", "macosx"}

source = {
  url = "git+https://github.com/cuongntr/kong-openid-connect-plugin.git",
  tag = "v1.0.0"
}

description = {
  summary = "A Kong plugin for OpenID Connect authentication (Kong 3.0+ compatible)",
  detailed = [[
    This plugin provides OpenID Connect (OIDC) authentication capabilities for Kong API Gateway.
    It supports the Authorization Code flow, token introspection, session management,
    and flexible configuration options for various OIDC providers.
    Compatible with Kong 3.0+ (no BasePlugin dependency).
  ]],
  homepage = "https://github.com/cuongntr/kong-openid-connect-plugin",
  license = "MIT"
}

dependencies = {
  "lua >= 5.1",
  "lua-resty-openidc >= 1.7.0",
  "lua-resty-session >= 2.24",
  "lua-resty-http >= 0.15",
  "lua-cjson >= 2.1.0"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins." .. pluginName .. ".handler"] = "kong/plugins/" .. pluginName .. "/handler.lua",
    ["kong.plugins." .. pluginName .. ".schema"] = "kong/plugins/" .. pluginName .. "/schema.lua",
    ["kong.plugins." .. pluginName .. ".utils"] = "kong/plugins/" .. pluginName .. "/utils.lua"
  }
}