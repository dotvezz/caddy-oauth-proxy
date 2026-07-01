# caddy-oauth-proxy

An OAuth 2.0 reverse proxy plugin for [Caddy v2](https://caddyserver.com/). It acts as an authentication middleware that intercepts unauthenticated requests, redirects users through a full OAuth 2.0 Authorization Code flow with PKCE, and then forwards the upstream request with the user's access token in the `Authorization` header.

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
  - [Unauthenticated Request (No Cookie)](#unauthenticated-request-no-cookie)
  - [Authenticated Request (Cookie Exists)](#authenticated-request-cookie-exists)
- [Supported Providers](#supported-providers)
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Building with xcaddy](#building-with-xcaddy)
  - [Using the Makefile](#using-the-makefile)
- [Configuration](#configuration)
  - [Global Configuration](#global-configuration)
  - [Per-Route Configuration](#per-route-configuration)
  - [Directive Reference](#directive-reference)
  - [Named Configurations](#named-configurations)
  - [Environment Variables](#environment-variables)
- [Example Caddyfile](#example-caddyfile)
- [Architecture](#architecture)
  - [Module Registration](#module-registration)
  - [Handler Lifecycle](#handler-lifecycle)
  - [Cookie State Machine](#cookie-state-machine)
  - [Token Refresh](#token-refresh)
  - [Provider Interface](#provider-interface)
- [Security](#security)
  - [PKCE (Proof Key for Code Exchange)](#pkce-proof-key-for-code-exchange)
  - [Cookie Encryption](#cookie-encryption)
  - [Cookie Properties](#cookie-properties)
- [Development](#development)
  - [Building](#building)
  - [Debugging](#debugging)
  - [Testing](#testing)
- [License](#license)

## Features

- OAuth 2.0 Authorization Code flow with PKCE (S256)
- Transparent token forwarding to upstream services via the `Authorization` header
- Automatic access token refresh using refresh tokens
- AES-GCM encrypted session cookies (optional)
- Configurable cookie name, secret, and max age
- Keycloak provider support (extensible provider interface)
- Global and per-route Caddyfile configuration with named config support
- Configurable error page for authentication failures
- Singleflight token exchange to prevent duplicate requests from concurrent callbacks
- Preserves the user's original URL across the authentication redirect

## How It Works

### Unauthenticated Request (No Cookie)

1. A user sends a request to a route protected by `oauth_proxy`.
2. The handler detects that no valid session cookie exists.
3. A PKCE code verifier is generated (32 random bytes, base64url-encoded).
4. The code verifier and the user's original URL are stored in an encrypted cookie.
5. A SHA-256 code challenge is derived from the verifier.
6. The user is redirected (HTTP 302) to the OAuth provider's authorization endpoint with the code challenge.
7. The user authenticates with the provider (e.g., Keycloak login screen).
8. The provider redirects back to the configured callback URL with an authorization code.
9. The handler reads the code verifier from the cookie, then exchanges the authorization code and verifier for tokens at the provider's token endpoint.
10. The tokens are stored in the encrypted cookie, replacing the verifier.
11. The user is redirected to their original URL.

### Authenticated Request (Cookie Exists)

1. A user sends a request with a valid session cookie.
2. The handler decrypts the cookie and retrieves the stored OAuth tokens.
3. If the access token is expired (or nearing expiry), the handler uses the refresh token to obtain a new access token from the provider and updates the cookie.
4. The access token is set in the request's `Authorization` header (as a Bearer token).
5. The request is passed to the next handler in the Caddy chain (e.g., `reverse_proxy`).

## Supported Providers

### Keycloak

The Keycloak provider connects to any Keycloak instance using its OpenID Connect endpoints. It requires:

| Setting         | Description                                                     |
|-----------------|-----------------------------------------------------------------|
| `base_url`      | The base URL of the Keycloak instance (e.g., `https://sso.example.com`) |
| `realm`         | The Keycloak realm to authenticate against                      |
| `client_id`     | The OAuth 2.0 client ID registered in Keycloak                  |
| `client_secret` | The OAuth 2.0 client secret                                     |

The provider constructs the following Keycloak endpoints automatically:

- Authorization: `{base_url}/realms/{realm}/protocol/openid-connect/auth`
- Token: `{base_url}/realms/{realm}/protocol/openid-connect/token`

The default scope is `openid`. PKCE with S256 is always used.

Additional providers can be implemented by satisfying the `Provider` interface (see [Provider Interface](#provider-interface)).

## Installation

### Prerequisites

- [Go](https://go.dev/) 1.24 or later
- [xcaddy](https://github.com/caddyserver/xcaddy) -- the Caddy build tool for plugins

### Building with xcaddy

```bash
xcaddy build --with github.com/dotvezz/caddy-oauth-proxy=.
```

This produces a `caddy` binary in the current directory with the `oauth_proxy` module compiled in.

### Using the Makefile

The included Makefile provides convenient targets:

```bash
# Install build tools (xcaddy and delve debugger)
make install

# Build the custom Caddy binary with debug symbols
make build

# Build and run Caddy with the example Caddyfile
make run

# Run tests
make test

# Remove the built binary
make clean
```

The Makefile automatically generates a random `COOKIE_SECRET` via `openssl rand -hex 16` and exports it for use in the Caddyfile. You can also place provider credentials in a `.env` file, which will be included automatically.

## Configuration

The `oauth_proxy` directive can be configured both as a **global option** (shared across all routes) and as a **per-route handler directive**. Per-route settings override globals.

### Global Configuration

Define shared settings in the global options block. These are inherited by all `oauth_proxy` handler invocations.

```caddyfile
{
    oauth_proxy {
        redirect_uri https://example.com/oauth/callback
        cookie {
            name _login
            secret {$COOKIE_SECRET}
            max_age 750h
        }
        keycloak {
            base_url {$KEYCLOAK_BASE_URL}
            realm {$KEYCLOAK_REALM}
            client_id {$KEYCLOAK_CLIENT_ID}
            client_secret {$KEYCLOAK_CLIENT_SECRET}
        }
    }
}
```

### Per-Route Configuration

Use the `oauth_proxy` directive inside route blocks to protect specific paths. When a global config exists, simply invoking `oauth_proxy` without a block will use the global settings.

```caddyfile
example.com {
    route /protected/* {
        oauth_proxy
        reverse_proxy backend:8080
    }

    route /public/* {
        reverse_proxy backend:8080
    }
}
```

### Directive Reference

#### Top-level directives

| Directive       | Description                                                      | Required |
|-----------------|------------------------------------------------------------------|----------|
| `redirect_uri`  | The full URL where the OAuth provider will redirect after login. Must match the callback route in your Caddyfile. | Yes |
| `error_page`    | Path to redirect to when authentication fails.                   | No       |
| `cookie { }`    | Cookie configuration block (see below).                          | No       |
| `keycloak { }`  | Keycloak provider configuration block (see below).               | Yes      |

#### Cookie block

| Directive  | Description                                                           | Default |
|------------|-----------------------------------------------------------------------|---------|
| `name`     | The name of the session cookie.                                       | (none)  |
| `secret`   | A secret key for AES-GCM encryption. Must be exactly 16, 24, or 32 bytes for AES-128, AES-192, or AES-256 respectively. If empty, the cookie is stored as plaintext JSON (not recommended for production). | (none) |
| `max_age`  | How long the cookie remains valid, as a Go duration string (e.g., `24h`, `750h`, `30m`). | (none) |

The `cookie` directive also supports a shorthand for setting just the name:

```caddyfile
cookie my_cookie_name {
    secret {$COOKIE_SECRET}
    max_age 24h
}
```

#### Keycloak block

| Directive       | Description                                      | Required |
|-----------------|--------------------------------------------------|----------|
| `base_url`      | Base URL of the Keycloak instance.                | Yes      |
| `realm`         | The Keycloak realm.                               | Yes      |
| `client_id`     | The OAuth 2.0 client ID.                          | Yes      |
| `client_secret` | The OAuth 2.0 client secret.                      | Yes      |

### Named Configurations

You can define multiple named configurations in the global block and reference them by key in route handlers. This is useful when different routes need different OAuth providers or settings.

```caddyfile
{
    oauth_proxy internal {
        # ... config for internal apps ...
    }

    oauth_proxy external {
        # ... config for external apps ...
    }
}

example.com {
    route /internal/* {
        oauth_proxy internal
        reverse_proxy internal-backend:8080
    }

    route /external/* {
        oauth_proxy external
        reverse_proxy external-backend:8080
    }
}
```

When no name is given, a default key is used internally.

### Environment Variables

The Caddyfile supports Caddy's standard `{$ENV_VAR}` syntax for environment variable substitution. Sensitive values such as secrets and client credentials should always be provided via environment variables rather than hardcoded in the Caddyfile.

## Example Caddyfile

Below is a full working example that protects a route with Keycloak authentication while leaving another route public:

```caddyfile
{
    debug
    metrics

    oauth_proxy {
        redirect_uri http://localhost:8080/oauth/callback
        cookie {
            name _login
            max_age 750h
            secret {$COOKIE_SECRET}
        }
        keycloak {
            base_url {$KEYCLOAK_BASE_URL}
            realm {$KEYCLOAK_REALM}
            client_id {$KEYCLOAK_CLIENT_ID}
            client_secret {$KEYCLOAK_CLIENT_SECRET}
        }
    }
}

http://localhost:8080 {
    route /oauth/callback {
        oauth_proxy
    }

    route /secure {
        oauth_proxy

        uri replace /secure /get
        reverse_proxy https://httpbin.org
    }

    route /public {
        uri replace /public /get
        reverse_proxy https://httpbin.org
    }
}
```

In this example:

- `/oauth/callback` handles the OAuth callback. The handler recognizes it because the path matches the `redirect_uri`.
- `/secure` is protected by `oauth_proxy`. Unauthenticated users are redirected to Keycloak; authenticated requests have their access token forwarded to the upstream.
- `/public` has no authentication and is accessible to anyone.

## Architecture

### Module Registration

The plugin registers itself as a Caddy module with the ID `http.handlers.oauth_proxy` and exposes the `oauth_proxy` Caddyfile directive. During Caddy startup, the `Provision` method initializes the configured provider, structured logger, and time function.

### Handler Lifecycle

The `ServeHTTP` method is the core request handler. It operates as a state machine based on the contents of the session cookie:

```
Request arrives
      |
      v
 [Check cookie state]
      |
      +--> cookieStateNoCookie ----> Generate PKCE verifier, store in cookie, redirect to provider
      |
      +--> cookieStateIncomplete --> If at callback path: exchange code for tokens, store in cookie, redirect to original URL
      |                             If not at callback path: treat as no cookie (restart flow)
      |
      +--> cookieStateActive ------> Optionally refresh token, set Authorization header, pass to next handler
```

### Cookie State Machine

The cookie progresses through three states:

| State                  | Contents                        | Meaning                                         |
|------------------------|----------------------------------|--------------------------------------------------|
| `cookieStateNoCookie`  | No cookie or invalid data        | User has not started authentication               |
| `cookieStateIncomplete`| Verifier + Original URL          | User has been redirected to the provider and the handler is waiting for the callback |
| `cookieStateActive`    | OAuth tokens (access + refresh)  | User is authenticated                            |

### Token Refresh

When a request arrives with an active cookie, the handler checks whether the access token is expired or will expire within 10 seconds. If so, it uses the refresh token to obtain a new access token from the provider. The refreshed token is written back to the cookie.

If the token's `Expiry` field is zero (some providers omit this), the handler falls back to parsing the `exp` claim directly from the JWT access token.

A `singleflight.Group` is used during token exchange to deduplicate concurrent requests that arrive with the same authorization code.

### Provider Interface

New OAuth providers can be added by implementing the `Provider` interface:

```go
type Provider interface {
    AuthURL(challenge, redirectURI string) (url.URL, error)
    GetTokens(code, verifier, redirectURI string) (oauth2.Token, error)
    Refresh(token oauth2.Token) (oauth2.Token, error)
}
```

- `AuthURL` -- Constructs the provider's authorization URL, including the PKCE code challenge and redirect URI.
- `GetTokens` -- Exchanges an authorization code and PKCE code verifier for access and refresh tokens.
- `Refresh` -- Uses a refresh token to obtain a new access token.

## Security

### PKCE (Proof Key for Code Exchange)

All authorization requests use PKCE with the S256 challenge method, as defined in [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636). This protects against authorization code interception attacks by binding the token request to the original authorization request, even for confidential clients.

The flow:

1. A 32-byte random code verifier is generated using `crypto/rand`.
2. The verifier is base64url-encoded and stored in the session cookie.
3. A SHA-256 hash of the verifier is base64url-encoded to create the code challenge.
4. The code challenge is sent to the authorization endpoint.
5. At token exchange, the original code verifier is sent to the token endpoint, which validates it against the stored challenge.

### Cookie Encryption

When a `secret` is configured, the session cookie is encrypted using **AES-GCM** (Galois/Counter Mode):

- The secret is used directly as the AES key (must be 16, 24, or 32 bytes).
- A random nonce is generated for each encryption operation using `crypto/rand`.
- The nonce is prepended to the ciphertext.
- The result is base64-encoded for storage in the cookie value.

When no secret is configured, cookie values are stored as plaintext base64-encoded JSON. This is acceptable for local development but should not be used in production.

### Cookie Properties

All session cookies are set with the following properties:

| Property   | Value                |
|------------|----------------------|
| `Path`     | `/`                  |
| `HttpOnly` | `true`               |
| `Secure`   | `true`               |
| `SameSite` | `Lax`                |
| `MaxAge`   | Configurable         |

The `HttpOnly` flag prevents JavaScript from accessing the cookie. The `Secure` flag ensures it is only transmitted over HTTPS. The `SameSite=Lax` policy provides CSRF protection while still allowing top-level navigations.

## Development

### Building

```bash
# Install xcaddy and delve
make install

# Build Caddy with the plugin
make build
```

The build uses `xcaddy` to compile a custom Caddy binary with this module included. The `XCADDY_DEBUG=1` flag enables debug symbols in the build.

### Debugging

```bash
make debug
```

This builds the binary and launches it under [Delve](https://github.com/go-delve/delve) with a remote debugging server on port 2345. Connect your IDE's Go debugger to `localhost:2345`.

### Testing

```bash
make test
```

Runs `go test -v ./...` across all packages.

### CI

The project includes a GitHub Actions workflow that runs `go test` on pushes and pull requests to the `main` branch.

## License

This project is licensed under the [MIT License](LICENSE).

Copyright (c) 2026 Ben Vezzani
