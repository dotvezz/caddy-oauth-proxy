package oauth

import (
	"fmt"
	"time"

	"github.com/dotvezz/caddy-oauth-proxy/providers/keycloak"

	"github.com/caddyserver/caddy/v2"
)

// Provision implements caddy.Provisioner
func (h *Handler) Provision(ctx caddy.Context) (err error) {
	// Wire up some deps
	h.slogger = ctx.Slogger()
	h.now = time.Now

	if h.ProviderConfig == nil {
		return fmt.Errorf("provider config is nil")
	}

	if h.ProviderConfig.Type == "keycloak" {
		h.provider, err = keycloak.NewProvider(*h.ProviderConfig)
		if err != nil {
			return fmt.Errorf("failed to create keycloak provider: %w", err)
		}
	}

	if h.provider == nil {
		return fmt.Errorf("provider is nil")
	}

	return nil
}
