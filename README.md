# Kong OpenID Connect Plugin 🔐

<div align="center">
  <h1>🏛️ 🔐 ⚡</h1>
  <p><strong>Kong API Gateway + OpenID Connect + High Performance</strong></p>
  <em>Secure your Kong API Gateway with OpenID Connect authentication</em>
</div>

A Kong plugin for OpenID Connect (OIDC) authentication that provides comprehensive authentication capabilities for Kong API Gateway.

## Features

- **OpenID Connect Support**: Full OIDC Authorization Code flow implementation
- **Token Introspection**: Support for bearer token validation via introspection endpoint
- **Flexible Session Management**: Multiple session storage options (cookie, memcache, redis, shared memory)
- **Header Injection**: Automatically adds authentication headers to upstream requests
- **Bearer-Only Mode**: Support for API-only authentication without redirects
- **Logout Handling**: Built-in logout functionality with configurable redirects
- **Group-Based Authorization**: Restrict access to users in specific groups (v1.1.0+)

## Installation

### Using LuaRocks

```bash
luarocks install kong-openid-connect
```

### Manual Installation

1. Clone this repository:
```bash
git clone https://github.com/cuongntr/kong-openid-connect-plugin.git
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
cp -r kong/plugins/kong-openid-connect /usr/local/share/lua/5.1/kong/plugins/
```

4. Enable the plugin in Kong configuration:
```bash
export KONG_PLUGINS=bundled,kong-openid-connect
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
| `redirect_uri_path` | string | `"/auth"` | Callback path for OIDC (deprecated) |
| `redirect_uri` | string | auto-generated | Full callback URI for OIDC |
| `redirect_uri_scheme` | string | auto-detected | Override scheme for redirect URI (http/https) |
| `redirect_uri_host` | string | auto-detected | Override hostname for redirect URI |
| `redirect_uri_port` | number | auto-detected | Override port for redirect URI (omit for 80/443) |
| `auto_detect_load_balancer` | boolean | `true` | Auto-detect load balancer using X-Forwarded headers |
| `logout_path` | string | `"/logout"` | Logout endpoint path |
| `timeout` | number | `10000` | HTTP timeout in milliseconds |

### Group Authorization Configuration (v1.1.0+)

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_group_authorization` | boolean | `false` | Enable group-based access control |
| `allowed_groups` | array | `[]` | List of groups allowed to access the resource |
| `group_claim_name` | string | `"groups"` | Name of the claim containing user groups |
| `group_claim_sources` | array | `["userinfo", "id_token", "access_token"]` | Sources to extract groups from |
| `group_claim_nested_key` | string | `nil` | Nested key for group claims (e.g., "roles") |
| `group_authorization_error_message` | string | `"Access denied: insufficient group permissions"` | Custom error message |
| `group_authorization_error_code` | number | `403` | HTTP status code for group authorization failures |

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
  --data "name=kong-openid-connect" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-oidc-provider/.well-known/openid-configuration" \
  --data "config.redirect_uri=https://my-domain.com/auth"
```

### Bearer Token Only Mode

```bash
curl -X POST http://kong-admin:8001/services/my-api/plugins \
  --data "name=kong-openid-connect" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-oidc-provider/.well-known/openid-configuration" \
  --data "config.bearer_only=true" \
  --data "config.introspection_endpoint=https://my-oidc-provider/introspect"
```

### Custom Session Storage (Redis)

```bash
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-openid-connect" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-oidc-provider/.well-known/openid-configuration" \
  --data "config.session_storage=redis" \
  --data "config.session_redis_host=127.0.0.1" \
  --data "config.session_redis_port=6379"
```

### Load Balancer Auto-Detection

**The plugin automatically detects load balancer scenarios!** 🚀

When Kong runs behind a load balancer (like yours: `port_maps = 80:8000, 443:8443`), the plugin:

1. **Detects X-Forwarded-Proto header** → Uses external scheme (https)
2. **Detects X-Forwarded-Host header** → Uses external hostname  
3. **Assumes standard ports** → Removes port from redirect URI (443 → omitted)

**For your configuration:**
- Kong internal: `https://dx-redis-insight.cmctelecom.vn:8443/auth`
- Auto-detected: `https://dx-redis-insight.cmctelecom.vn/auth` ✅

**No additional configuration needed!** Just enable the plugin:

```bash
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-openid-connect" \
  --data "config.client_id=redis-insight" \
  --data "config.client_secret=your-secret" \
  --data "config.discovery=https://auth.cmctelecom.vn/realms/dtu-cmctelecom/protocol/openid-connect/auth"
```

### Manual Port Mapping (if needed)

If auto-detection doesn't work, you can override manually:

```bash
# Remove port from redirect URI (for services behind load balancers)
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-openid-connect" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-oidc-provider/.well-known/openid-configuration" \
  --data "config.redirect_uri_host=my-public-domain.com" \
  --data "config.redirect_uri_scheme=https"

# Disable auto-detection
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-openid-connect" \
  --data "config.auto_detect_load_balancer=false" \
  --data "config.redirect_uri_port=8080"
```

### Group-Based Authorization (v1.1.0+)

**Restrict access to specific user groups:**

```bash
# Basic group authorization
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-openid-connect" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-oidc-provider/.well-known/openid-configuration" \
  --data "config.enable_group_authorization=true" \
  --data "config.allowed_groups[]=admin" \
  --data "config.allowed_groups[]=developers"

# Keycloak realm roles (nested groups)
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-openid-connect" \
  --data "config.client_id=my-client-id" \
  --data "config.client_secret=my-client-secret" \
  --data "config.discovery=https://my-keycloak/.well-known/openid-configuration" \
  --data "config.enable_group_authorization=true" \
  --data "config.allowed_groups[]=admin" \
  --data "config.allowed_groups[]=manager" \
  --data "config.group_claim_name=realm_access" \
  --data "config.group_claim_nested_key=roles"

# Custom error message and status code
curl -X POST http://kong-admin:8001/services/my-service/plugins \
  --data "name=kong-openid-connect" \
  --data "config.enable_group_authorization=true" \
  --data "config.allowed_groups[]=premium_users" \
  --data "config.group_authorization_error_message=Premium subscription required" \
  --data "config.group_authorization_error_code=402"

# Groups from access token only (for API-only scenarios)
curl -X POST http://kong-admin:8001/services/my-api/plugins \
  --data "name=kong-openid-connect" \
  --data "config.bearer_only=true" \
  --data "config.enable_group_authorization=true" \
  --data "config.allowed_groups[]=api_users" \
  --data "config.group_claim_sources[]=access_token"
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

### Group Authorization Flow (v1.1.0+)

1. **User Authentication**: User successfully authenticates via OIDC
2. **Group Extraction**: Plugin extracts user groups from configured sources:
   - **Userinfo Endpoint**: Most reliable, requires API call
   - **ID Token Claims**: Faster, embedded in JWT token
   - **Access Token Claims**: For API-only scenarios
3. **Group Validation**: Plugin checks if user belongs to any allowed group
4. **Authorization Decision**: 
   - ✅ **Allow**: User has required group membership
   - ❌ **Deny**: Return 403 Forbidden (or custom error)

## Group Sources Support

### Userinfo Endpoint (`/userinfo`)
```json
{
  "sub": "user123",
  "name": "John Doe",
  "groups": ["admin", "developers"]
}
```

### ID Token Claims
```json
{
  "sub": "user123",
  "groups": ["admin", "developers"],
  "realm_access": {
    "roles": ["admin", "manager"]
  }
}
```

### Access Token Claims (JWT)
```json
{
  "sub": "user123",
  "scope": "openid profile",
  "groups": ["api_users"],
  "resource_access": {
    "my-app": {
      "roles": ["admin"]
    }
  }
}
```

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

- Kong >= 3.0 (uses modern plugin structure, no BasePlugin dependency)
- OpenResty >= 1.15.8.1
- Lua >= 5.1

**Note**: This plugin is specifically designed for Kong 3.0+ and does not use the deprecated `BasePlugin` class.

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
- GitHub Issues: https://github.com/cuongntr/kong-openid-connect-plugin/issues
- Kong Community: https://discuss.konghq.com/

## Changelog

### v1.1.0
- **Group-Based Authorization**: Restrict access to users in specific groups
- **Multi-Source Group Extraction**: Extract groups from userinfo, ID tokens, or access tokens
- **Nested Group Claims**: Support for complex group structures (e.g., Keycloak realm roles)
- **Configurable Error Handling**: Custom error messages and HTTP status codes
- **Bearer Token Group Authorization**: Group validation for API-only scenarios
- **JWT Token Parsing**: Built-in JWT payload decoding for group extraction
- **Flexible Group Sources**: Configure priority and sources for group extraction

### v1.0.0
- Initial release
- OpenID Connect Authorization Code flow support
- Bearer token introspection
- Flexible session management
- Configurable header injection
- Logout functionality