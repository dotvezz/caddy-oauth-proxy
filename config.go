package oauth

import "github.com/dotvezz/caddy-oauth-proxy/providers"

type CookieConfig struct {
	Name   string `json:"name,omitempty"`
	Secret string `json:"secret,omitempty"`
	MaxAge int    `json:"max_age,omitempty"`
}

type Config struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
	ErrorPage   string `json:"error_page,omitempty"`

	AllowUnauthenticated bool `json:"allow_unauthenticated"`

	CookieConfig   *CookieConfig     `json:"cookie,omitempty"`
	ProviderConfig *providers.Config `json:"provider_config,omitempty"`
}
