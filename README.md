# Kong OIDC Plugin

A Kong plugin for OpenID Connect (OIDC) authentication that provides comprehensive authentication capabilities for Kong API Gateway.

## Features

- **OpenID Connect Support**: Full OIDC Authorization Code flow implementation
- **Token Introspection**: Support for bearer token validation via introspection endpoint
- **Flexible Session Management**: Multiple session storage options (cookie, memcache, redis, shared memory)
- **Header Injection**: Automatically adds authentication headers to upstream requests
- **Bearer-Only Mode**: Support for API-only authentication without redirects
- **Logout Handling**: Built-in logout functionality with configurable redirects

## Installation

### Using LuaRocks

```bash
luarocks install kong-oidc
```

### Manual Installation

1. Clone this repository:
```bash
git clone https://github.com/cuongnt/kong-openid-connect-plugin.git
cd kong-openid-connect-plugin
```

2. Install dependencies:
```bash
luarocks install lua-resty-openidc
luarocks install lua-resty-session
luarocks install lua-resty-http
```

3. Copy plugin files to Kong plugins directory:
```bash
cp -r kong/plugins/kong-oidc /usr/local/share/lua/5.1/kong/plugins/
```

4. Enable the plugin in Kong configuration:
```bash
export KONG_PLUGINS=bundled,kong-oidc
```

## Configuration

### Required Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_id` | string | OIDC Client ID |
| `client_secret` | string | OIDC Client Secret |
| `discovery` | string | OIDC Discovery endpoint URL |

### Optional Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `scope` | string | `"openid"` | OAuth2 scope |
| `response_type` | string | `"code"` | OAuth2 response type |
| `ssl_verify` | boolean | `false` | Verify SSL certificates |
| `bearer_only` | boolean | `false` | API-only mode without redirects |
| `realm` | string | `"kong"` | Authentication realm |
| `redirect_uri_path` | string | `"/auth"` | Callback path for OIDC |
| `logout_path` | string | `"/logout"` | Logout endpoint path |
| `timeout` | number | `10000` | HTTP timeout in milliseconds |

### Session Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `session_secret` | string | auto-generated | Session encryption secret |
| `session_cookie_name` | string | `"session"` | Session cookie name |
| `session_cookie_lifetime` | number | `3600` | Cookie lifetime in seconds |
| `session_storage` | string | `"cookie"` | Storage type: cookie, memcache, redis, shm |

### Header Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `access_token_header_name` | string | `"X-Access-Token"` | Access token header name |
| `id_token_header_name` | string | `"X-Id-Token"` | ID token header name |
| `user_info_header_name` | string | `"X-Userinfo"` | User info header name |

## Usage Examples

### Basic OIDC Authentication

```bash
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-oidc" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-oidc-provider/.well-known/openid-configuration"
```

### Bearer Token Only Mode

```bash
curl -X POST http://kong-admin:8001/services/my-api/plugins \
  --data "name=kong-oidc" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-oidc-provider/.well-known/openid-configuration" \
  --data "config.bearer_only=true" \
  --data "config.introspection_endpoint=https://my-oidc-provider/introspect"
```

### Custom Session Storage (Redis)

```bash
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-oidc" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-oidc-provider/.well-known/openid-configuration" \
  --data "config.session_storage=redis" \
  --data "config.session_redis_host=127.0.0.1" \
  --data "config.session_redis_port=6379"
```

## Authentication Flow

### Authorization Code Flow

1. User accesses protected resource
2. Plugin redirects to OIDC provider for authentication
3. User authenticates with OIDC provider
4. Provider redirects back to Kong with authorization code
5. Plugin exchanges code for tokens
6. User session is established
7. Subsequent requests use the established session

### Bearer Token Flow

1. Client sends request with `Authorization: Bearer <token>` header
2. Plugin validates token via introspection endpoint
3. If valid, request proceeds to upstream service
4. Plugin adds user information headers to upstream request

## Upstream Headers

The plugin automatically adds the following headers to upstream requests:

- `X-Access-Token`: Base64 encoded access token
- `X-Id-Token`: Base64 encoded ID token
- `X-Userinfo`: Base64 encoded user information (JSON)

## Logout

To logout a user, direct them to the configured logout path (default: `/logout`). The plugin will:

1. Destroy the user session
2. Redirect to `logout_redirect_uri` if configured
3. Return a success message if no redirect URI is set

## Dependencies

- `lua-resty-openidc >= 1.7.0`: Core OIDC functionality
- `lua-resty-session >= 2.24`: Session management
- `lua-resty-http >= 0.15`: HTTP client
- `lua-cjson >= 2.1.0`: JSON handling

## Compatibility

- Kong >= 2.0
- OpenResty >= 1.15.8.1
- Lua >= 5.1

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

For issues and questions:
- GitHub Issues: https://github.com/cuongnt/kong-openid-connect-plugin/issues
- Kong Community: https://discuss.konghq.com/

## Changelog

### v1.0.0
- Initial release
- OpenID Connect Authorization Code flow support
- Bearer token introspection
- Flexible session management
- Configurable header injection
- Logout functionality