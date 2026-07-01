package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

var (
	_ caddy.Provisioner           = (*Handler)(nil)
	_ caddyhttp.MiddlewareHandler = (*Handler)(nil)
)

func init() {
	caddy.RegisterModule(Handler{})
}

type slogger interface {
	Error(string, ...any)
	Info(string, ...any)
}

type Handler struct {
	Config

	// ConfigKey (json:"config_key") allows a handler to optionally specify a config key to load from the global
	// config.
	//
	// This allows global configs to define the oauth provider settings etc, with optional named configs in case multiple
	// are needed.
	ConfigKey string `json:"config_key"`

	provider     Provider
	singleFlight singleflight.Group

	slogger
	now func() time.Time
}

func (h Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.oauth_proxy",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) (err error) {
	switch h.cookieState(r) {
	case cookieStateNoCookie:
		if !h.AllowUnauthenticated {
			return h.handleNoCookie(w, r)
		}
	case cookieStateIncomplete:
		ruri, _ := url.Parse(h.RedirectURI)

		if r.URL.Path == ruri.Path {
			return h.handleIncomplete(w, r)
		}
		return h.handleNoCookie(w, r)
	case cookieStateActive:
		h.handleActive(w, r)
	}

	return next.ServeHTTP(w, r)
}

func (h *Handler) handleNoCookie(w http.ResponseWriter, r *http.Request) (err error) {
	cv := CookieVal{}

	data := make([]byte, 32)
	if _, err = rand.Read(data); err != nil {
		return fmt.Errorf("failed to generate random bytes for PKCE: %w", err)
	}

	cv.Verifier = base64.RawURLEncoding.EncodeToString(data)
	cv.OriginalURL = r.URL.String()

	hash := sha256.Sum256([]byte(cv.Verifier))

	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	_ = h.setCookie(w, cv)

	redirectURL, err := h.provider.AuthURL(challenge, h.RedirectURI)
	if err != nil {
		return fmt.Errorf("failed to generate auth URL: %w", err)
	}

	w.Header().Set("Location", redirectURL.String())
	w.WriteHeader(http.StatusFound)

	return nil
}

func (h *Handler) handleIncomplete(w http.ResponseWriter, r *http.Request) (err error) {
	code := r.URL.Query().Get("code")
	if code == "" { // If we landed here without a callback code, wtf start over
		return h.handleNoCookie(w, r)
	}

	val, err := h.getCookieVal(r)
	if err != nil { // If we don't have a valid cookie, super wtf and still start over
		return h.handleNoCookie(w, r)
	}

	if val.Verifier == "" { // If we don't have a verifier, wtf the third and start over
		return h.handleNoCookie(w, r)
	}

	var t oauth2.Token
	t, err = h.getTokens(code, val.Verifier)
	if err != nil { // Okay there's a pattern here. TODO: come up with a better error redirect strategy
		return h.handleNoCookie(w, r)
	}

	newVal := CookieVal{Token: t}
	err = h.setCookie(w, newVal)
	if err != nil { // TODO: look up
		return h.handleNoCookie(w, r)
	}

	w.Header().Set("Location", val.OriginalURL)
	w.WriteHeader(http.StatusFound)

	return nil
}

func (h *Handler) getTokens(code, verifier string) (ts oauth2.Token, err error) {
	_, _, _ = h.singleFlight.Do(code, func() (any, error) {
		ts, err = h.provider.GetTokens(code, verifier, h.RedirectURI)
		if err != nil {
			return nil, fmt.Errorf("failed to get tokens: %w", err)
		}

		return nil, nil
	})

	return
}

func (h *Handler) handleActive(w http.ResponseWriter, r *http.Request) {
	val, err := h.getCookieVal(r)
	if err != nil {
		return
	}

	if needsRefresh(val) {
		val.Token, err = h.provider.Refresh(val.Token)
		if err != nil {
			err = fmt.Errorf("failed to refresh tokens: %w", err)
			return
		}
		err = h.setCookie(w, val)
		if err != nil {
			err = fmt.Errorf("failed to set cookie: %w", err)
			return
		}
	}

	r.Header.Set("Authorization", fmt.Sprintf("%s %s", val.Token.Type(), val.Token.AccessToken))
}

func getJWTExp(t string) (time.Time, error) {
	claims := struct {
		exp int64 `json:"exp"`
	}{}

	parts := strings.Split(t, ".")
	if len(parts) != 3 {
		return time.Time{}, fmt.Errorf("unexpected jwt format")
	}

	bs, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to decode token: %w", err)
	}

	err = json.Unmarshal(bs, &claims)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to unmarshal token: %w", err)
	}

	return time.Unix(claims.exp, 0), nil
}

func needsRefresh(val CookieVal) bool {
	exp := val.Token.Expiry
	if exp.IsZero() { // We need to get the exp time from the token itself if there's nothing there.
		var err error
		exp, err = getJWTExp(val.Token.AccessToken)
		if err != nil { // If we can't determine the exp time then just assume there's no refresh
			return false
		}
	}

	// TODO: Configurable eager token refresh splay
	return val.Token.Expiry.Before(time.Now().Add(-(time.Second * 10)))
}
