package oauth

import (
	"time"

	"github.com/dotvezz/caddy-oauth-proxy/providers"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

const (
	defaultKey = " default " // Spaces to make it hard to parse an accidentally colliding key from Caddyfile
	moduleName = "oauth_proxy"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective(moduleName, parseCaddyfile)
	httpcaddyfile.RegisterGlobalOption(moduleName, registerGlobalOption)
}

type caddyfileHelper interface {
	NextBlock(int) bool
	Nesting() int
	Next() bool
	Args(...*string) bool
	Val() string
	NextArg() bool
	ArgErr() error
	RemainingArgs() []string
	Errf(format string, args ...any) error
}

// registerGlobalOption registers global options for the oauth_proxy directive.
func registerGlobalOption(d *caddyfile.Dispenser, existing any) (any, error) {
	d.Next() // Consume the directive name

	if existing == nil { // If configMap is nil, initialize it with a map
		existing = make(map[string]Config)
	}

	var (
		configMap map[string]Config
		ok        bool
	)
	if configMap, ok = existing.(map[string]Config); !ok {
		return nil, d.Errf("invalid configMap type")
	}

	var key string
	if !d.Args(&key) {
		key = defaultKey
	}

	c := Config{}
	err := parseFromCustomHelper(d, &c)
	configMap[key] = c
	return configMap, err
}

// parseCaddyfile parses the oauth_proxy directive from Caddyfile.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	hnd := new(Handler)
	h.Next() // consume directive name

	if !h.Args(&hnd.ConfigKey) {
		hnd.ConfigKey = defaultKey
	}

	existing := h.Option(moduleName)
	if existing != nil {
		if _, ok := existing.(map[string]Config); !ok {
			return nil, h.Errf("invalid global config type %T, expected %T", existing, map[string]Config{})
		}

		if global, ok := existing.(map[string]Config)[hnd.ConfigKey]; ok {
			mapConfigFromGlobal(&global, &hnd.Config)
		}
	}

	err := parseFromCustomHelper(h, &hnd.Config)
	return hnd, err
}

func mapConfigFromGlobal(global *Config, config *Config) {
	if global.CookieConfig != nil {
		config.CookieConfig = new(*global.CookieConfig)
	}
	if global.ProviderConfig != nil {
		config.ProviderConfig = new(*global.ProviderConfig)
	}
	if global.ErrorPage != "" {
		config.ErrorPage = global.ErrorPage
	}
	if global.RedirectURI != "" {
		config.RedirectURI = global.RedirectURI
	}
}

// parseFromCustomHelper handles the actual parsing of the caddyfile directive, whether global or in a handler
//
//	oauth_proxy {
//		callback_url /oauth/callback
//		error_page /error.html
//		cookie {
//			name oauth_session
//			secret some-32-byte-secret
//		}
//		keycloak {
//			base_url http://localhost:8080
//			realm master
//			client_id my-client
//			client_secret client-secret
//		}
//	}
func parseFromCustomHelper(h caddyfileHelper, c *Config) error {
	for h.NextBlock(0) {
		key := h.Val()
		switch key {
		case "redirect_uri":
			if !h.NextArg() {
				return h.ArgErr()
			}
			c.RedirectURI = h.Val()
		case "error_page":
			if !h.NextArg() {
				return h.ArgErr()
			}
			c.ErrorPage = h.Val()
		case "cookie":
			if c.CookieConfig == nil {
				c.CookieConfig = new(CookieConfig)
			}
			if args := h.RemainingArgs(); len(args) == 1 {
				c.CookieConfig.Name = args[0]
			}
			for h.NextBlock(1) {
				subKey := h.Val()
				switch subKey {
				case "name":
					if !h.NextArg() {
						return h.ArgErr()
					}
					c.CookieConfig.Name = h.Val()
				case "max_age":
					if !h.NextArg() {
						return h.ArgErr()
					}
					s := h.Val()
					var err error
					var d time.Duration
					if d, err = time.ParseDuration(s); err != nil {
						return h.Errf("invalid max_age value: %s", s)
					}
					c.CookieConfig.MaxAge = int(d.Seconds())
				case "secret":
					if !h.NextArg() {
						return h.ArgErr()
					}
					c.CookieConfig.Secret = h.Val()
				default:
					return h.Errf("unknown cookie option: %s", subKey)
				}
			}
		case "keycloak":
			c.ProviderConfig = &providers.Config{
				Type: "keycloak",
			}

			for h.NextBlock(1) {
				subKey := h.Val()
				switch subKey {
				case "base_url":
					if !h.NextArg() {
						return h.ArgErr()
					}
					c.ProviderConfig.BaseURL = h.Val()
				case "realm":
					if !h.NextArg() {
						return h.ArgErr()
					}
					c.ProviderConfig.Realm = h.Val()
				case "client_id":
					if !h.NextArg() {
						return h.ArgErr()
					}
					c.ProviderConfig.ClientID = h.Val()
				case "client_secret":
					if !h.NextArg() {
						return h.ArgErr()
					}
					c.ProviderConfig.ClientSecret = h.Val()
				default:
					return h.Errf("unknown keycloak option: %s", subKey)
				}
			}
		default:
			return h.Errf("unknown option: %s", key)
		}
	}

	return nil
}
