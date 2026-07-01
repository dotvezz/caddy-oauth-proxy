package oauth

import (
	"net/url"

	"golang.org/x/oauth2"
)

type Provider interface {
	AuthURL(challenge, redirectURI string) (url.URL, error)
	GetTokens(code, verifier, redirectURI string) (oauth2.Token, error)
	Refresh(token oauth2.Token) (oauth2.Token, error)
}
