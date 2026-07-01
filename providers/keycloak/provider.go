package keycloak

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/dotvezz/caddy-oauth-proxy/providers"

	"golang.org/x/oauth2"
)

func NewProvider(cfg providers.Config) (*Provider, error) {
	p := &Provider{
		realm:        cfg.Realm,
		clientID:     cfg.ClientID,
		clientSecret: cfg.ClientSecret,
	}

	timeout := 10 * time.Second
	if cfg.RequestTimeout > 0 {
		timeout = time.Duration(cfg.RequestTimeout)
	}

	p.client = &http.Client{
		Timeout: timeout,
	}

	p.baseURL = cfg.BaseURL

	return p, nil
}

type Provider struct {
	baseURL      string
	realm        string
	clientID     string
	clientSecret string

	client *http.Client
}

func (p *Provider) AuthURL(challenge, redirectURI string) (url.URL, error) {
	u, err := url.Parse(p.baseURL)
	if err != nil {
		err = fmt.Errorf("error parsing base URL for Keycloak: %w", err)
		return url.URL{}, err
	}

	u.Path = fmt.Sprintf("realms/%s/protocol/openid-connect/auth", p.realm)

	q := url.Values{
		"response_type":         {"code"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"client_id":             {p.clientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {"openid"},
		// "state":                 {"TODO"},
	}

	u.RawQuery = q.Encode()

	return *u, nil
}

func (p *Provider) tokenURL() (url.URL, error) {
	u, err := url.Parse(p.baseURL)
	if err != nil {
		return url.URL{}, err
	}

	u.Path = fmt.Sprintf("/realms/%s/protocol/openid-connect/token", p.realm)

	return *u, nil
}

func (p *Provider) doTokenRequest(vs url.Values) (oauth2.Token, error) {
	var r *http.Response
	var t oauth2.Token

	u, err := p.tokenURL()
	if err != nil {
		return oauth2.Token{}, err
	}

	rd := strings.NewReader(vs.Encode())
	r, err = p.client.Post(u.String(), "application/x-www-form-urlencoded", rd)
	if err != nil {
		return t, err
	}

	var bs []byte
	bs, err = io.ReadAll(r.Body)
	if r.StatusCode != http.StatusOK {
		return t, fmt.Errorf("unexpected status code: %d", r.StatusCode)
	}

	err = json.Unmarshal(bs, &t)
	if err != nil {
		return t, fmt.Errorf("error unmarshalling tokens: %w", err)
	}

	return t, err
}

func (p *Provider) GetTokens(code, verifier, redirectURI string) (oauth2.Token, error) {
	vs := url.Values{}
	vs.Set("grant_type", "authorization_code")
	vs.Set("code", code)
	vs.Set("code_verifier", verifier)
	vs.Set("client_id", p.clientID)
	vs.Set("client_secret", p.clientSecret)
	vs.Set("redirect_uri", redirectURI)

	return p.doTokenRequest(vs)
}

func (p *Provider) Refresh(token oauth2.Token) (oauth2.Token, error) {
	vs := url.Values{}
	vs.Set("grant_type", "refresh_token")
	vs.Set("client_id", p.clientID)
	vs.Set("client_secret", p.clientSecret)
	vs.Set("refresh_token", token.RefreshToken)

	return p.doTokenRequest(vs)
}
