package oauth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
)

type CookieVal struct {
	Verifier    string `json:"verifier,omitempty"`
	OriginalURL string `json:"original_url,omitempty"`

	Token oauth2.Token `json:"token,omitempty"`
}

const (
	cookieStateNoCookie = iota
	cookieStateIncomplete
	cookieStateActive
)

func (h *Handler) aesGCM() (aesGCM cipher.AEAD, err error) {
	var block cipher.Block
	block, err = aes.NewCipher([]byte(h.CookieConfig.Secret))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher block: %w", err)
	}

	aesGCM, err = cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	return aesGCM, nil
}

func (h *Handler) getCookieVal(r *http.Request) (cv CookieVal, err error) {
	var cookie *http.Cookie

	cookie, err = r.Cookie(h.CookieConfig.Name)
	if err != nil {
		return
	}

	var bs []byte
	bs, err = base64.StdEncoding.DecodeString(cookie.Value)
	if err != nil {
		return
	}

	if h.CookieConfig.Secret != "" {
		var aesGCM cipher.AEAD
		aesGCM, err = h.aesGCM()
		if err != nil {
			return cv, fmt.Errorf("failed to create GCM cipher to decrypt cookie: %w", err)
		}

		nonceSize := aesGCM.NonceSize()
		if len(cookie.Value) < nonceSize {
			return cv, fmt.Errorf("cookie value too short to decrypt")
		}

		// Split the nonce and actual ciphertext
		iv, bareVal := bs[:nonceSize], bs[nonceSize:]

		bs, err = aesGCM.Open(nil, iv, bareVal, nil)
		if err != nil {
			return cv, fmt.Errorf("failed to decrypt cookie: %w", err)
		}
	}

	if err = json.Unmarshal(bs, &cv); err != nil {
		return cv, fmt.Errorf("failed to unmarshal cookie value: %w", err)
	}

	return
}

func (h *Handler) cookieState(r *http.Request) int {
	val, err := h.getCookieVal(r)
	if err != nil {
		return cookieStateNoCookie
	}

	if len(val.Verifier) > 0 {
		return cookieStateIncomplete
	}

	if len(val.Token.AccessToken) > 0 {
		return cookieStateActive
	}

	return cookieStateNoCookie
}

func (h *Handler) setCookie(w http.ResponseWriter, val CookieVal) error {
	bs, err := json.Marshal(val)
	if err != nil {
		return fmt.Errorf("failed to marshal cookie value: %w", err)
	}

	if h.CookieConfig.Secret != "" {
		var aesGCM cipher.AEAD
		aesGCM, err = h.aesGCM()
		if err != nil {
			return fmt.Errorf("failed to create GCM cipher to encrypt cookie: %w", err)
		}

		iv := make([]byte, aesGCM.NonceSize())
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			return err
		}

		bs = aesGCM.Seal(iv, iv, bs, nil)
	}

	c := &http.Cookie{
		Name:     h.CookieConfig.Name,
		Value:    base64.StdEncoding.EncodeToString(bs),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   h.CookieConfig.MaxAge,
	}

	http.SetCookie(w, c)

	return nil
}
