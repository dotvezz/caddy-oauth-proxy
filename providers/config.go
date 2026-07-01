package providers

import "time"

type Config struct {
	Type           string       `json:"type"`
	BaseURL        string       `json:"base_url,omitempty"`
	Realm          string       `json:"realm,omitempty"`
	ClientID       string       `json:"client_id,omitempty"`
	ClientSecret   string       `json:"client_secret,omitempty"`
	RequestTimeout JSONDuration `json:"request_timeout,omitempty"`
}

type JSONDuration time.Duration

func (d *JSONDuration) UnmarshalJSON(bytes []byte) (err error) {
	var parsed time.Duration
	if parsed, err = time.ParseDuration(string(bytes)); err != nil {
		return err
	}

	*d = JSONDuration(parsed)
	return nil
}

func (d *JSONDuration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + time.Duration(*d).String() + `"`), nil
}
