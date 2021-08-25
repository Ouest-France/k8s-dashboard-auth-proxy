package proxy

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func Test_tokenExpired(t *testing.T) {
	type args struct {
		rawToken string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{
			name: "invalid jwt token",
			args: args{
				rawToken: "123456",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "invalid base64 jwt payload",
			args: args{
				rawToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.inval*d.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "invalid json jwt payload",
			args: args{
				rawToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aW52YWxpZA.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			},
			want:    false,
			wantErr: true,
		},
		{
			name: "expired jwt token",
			args: args{
				rawToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE2Mjk4NDIwOTN9.IWwDGwVvBdW_giGdwv_yT-vE5zjnjX5FeLebgiN1ljI",
			},
			want:    true,
			wantErr: false,
		},
		{
			name: "not expired jwt token",
			args: args{
				rawToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjI2Mjk4NDIwOTN9.gpoS_EeoydtmDfDWg_bq1ZMqwqIkqx5XXabWY9iImao",
			},
			want:    false,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tokenExpired(tt.args.rawToken)
			if (err != nil) != tt.wantErr {
				t.Errorf("tokenExpired() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("tokenExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_splitToken(t *testing.T) {
	type args struct {
		token string
		size  int
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "one part",
			args: args{
				token: "012345",
				size:  10,
			},
			want:    []string{"012345"},
			wantErr: false,
		},
		{
			name: "two parts",
			args: args{
				token: "0123456789012345",
				size:  10,
			},
			want:    []string{"0123456789", "012345"},
			wantErr: false,
		},
		{
			name: "three parts",
			args: args{
				token: "012345678901234567890123456789",
				size:  10,
			},
			want:    []string{"0123456789", "0123456789", "0123456789"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := splitToken(tt.args.token, tt.args.size); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("splitToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_mergeToken(t *testing.T) {
	type args struct {
		tokenParts []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "one part",
			args: args{
				tokenParts: []string{"012345"},
			},
			want: "012345",
		},
		{
			name: "two parts",
			args: args{
				tokenParts: []string{"0123456789", "012345"},
			},
			want: "0123456789012345",
		},
		{
			name: "three parts",
			args: args{
				tokenParts: []string{"0123456789", "0123456789", "0123456789"},
			},
			want: "012345678901234567890123456789",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mergeToken(tt.args.tokenParts); got != tt.want {
				t.Errorf("mergeToken() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_setTokenCookie(t *testing.T) {
	type args struct {
		token string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{
			name: "one part",
			args: args{
				token: "012345",
			},
			want: map[string]string{
				"proxy_auth_token_parts": "1",
				"proxy_auth_token_0":     "012345",
			},
		},
		{
			name: "two parts",
			args: args{
				token: "0123456789012345",
			},
			want: map[string]string{
				"proxy_auth_token_parts": "2",
				"proxy_auth_token_0":     "0123456789",
				"proxy_auth_token_1":     "012345",
			},
		},
		{
			name: "three parts",
			args: args{
				token: "012345678901234567890123456789",
			},
			want: map[string]string{
				"proxy_auth_token_parts": "3",
				"proxy_auth_token_0":     "0123456789",
				"proxy_auth_token_1":     "0123456789",
				"proxy_auth_token_2":     "0123456789",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			setTokenCookie(recorder, tt.args.token, 10)
			request := &http.Request{Header: http.Header{"Cookie": recorder.HeaderMap["Set-Cookie"]}} //nolint

			for wantCookieName, wantCookieValue := range tt.want {
				cookie, err := request.Cookie(wantCookieName)
				if err != nil {
					if !tt.wantErr {
						t.Errorf("setTokenCookie() unwanted error = %v", err)
					}
					return
				}

				if wantCookieValue != cookie.Value {
					t.Errorf("setTokenCookie() = %v, want %v", cookie.Value, wantCookieValue)
				}
			}
		})
	}
}

func Test_getTokenCookie(t *testing.T) {
	type args struct {
		cookies []string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "missing proxy_auth_token_parts",
			args: args{
				cookies: []string{
					"proxy_auth_token_0=012345",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "one part",
			args: args{
				cookies: []string{
					"proxy_auth_token_parts=1",
					"proxy_auth_token_0=012345",
				},
			},
			want:    "012345",
			wantErr: false,
		},
		{
			name: "three parts",
			args: args{
				cookies: []string{
					"proxy_auth_token_parts=3",
					"proxy_auth_token_0=0123456789",
					"proxy_auth_token_1=0123456789",
					"proxy_auth_token_2=0123456789",
				},
			},
			want:    "012345678901234567890123456789",
			wantErr: false,
		},
		{
			// We can't error for invalid smaller parts number
			name: "wrong smaller proxy_auth_token_parts",
			args: args{
				cookies: []string{
					"proxy_auth_token_parts=2",
					"proxy_auth_token_0=0123456789",
					"proxy_auth_token_1=0123456789",
					"proxy_auth_token_2=0123456789",
				},
			},
			want:    "01234567890123456789",
			wantErr: false,
		},
		{
			name: "wrong higher proxy_auth_token_parts",
			args: args{
				cookies: []string{
					"proxy_auth_token_parts=4",
					"proxy_auth_token_0=0123456789",
					"proxy_auth_token_1=0123456789",
					"proxy_auth_token_2=0123456789",
				},
			},
			want:    "",
			wantErr: true,
		},
		{
			name: "empty token",
			args: args{
				cookies: []string{
					"proxy_auth_token_parts=1",
					"proxy_auth_token_0=",
				},
			},
			want:    "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := &http.Request{Header: http.Header{"Cookie": tt.args.cookies}}

			got, err := getTokenCookie(request)
			if (err != nil) != tt.wantErr {
				t.Errorf("getTokenCookie() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("getTokenCookie() = %v, want %v", got, tt.want)
			}
		})
	}
}
