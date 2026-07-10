package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func fakeJWT(claims map[string]any) string {
	j, _ := json.Marshal(claims)
	return "." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s", j))) + "."
}

func Test_getJWTExp(t *testing.T) {
	type args struct {
		t string
	}
	tests := []struct {
		name    string
		args    args
		want    time.Time
		wantErr bool
	}{
		{
			name: "expires 2025-01-01 00:00:01",
			args: args{
				t: fakeJWT(map[string]any{
					"exp": time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC).Unix(),
				}),
			},
			want:    time.Date(2025, 1, 1, 0, 0, 1, 0, time.UTC),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getJWTExp(tt.args.t)
			if (err != nil) != tt.wantErr {
				t.Errorf("getJWTExp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getJWTExp() got = %v, want %v", got, tt.want)
			}
		})
	}
}
