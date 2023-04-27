package proxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"

	"github.com/Ouest-France/k8s-dashboard-auth-proxy/provider"
)

func proxyHandler(target string, authProvider provider.Provider) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// get token or redirect to login
		token, err := getTokenCookie(r)
		if err != nil {
			log.Printf("failed to get cookie: %s", err)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// Switch on auth provider
		switch authProvider := authProvider.(type) {
		case *provider.ProviderAwsAdfs:

			// Check if token is valid
			err = authProvider.Valid(token)
			if err == nil {
				break
			}

			// Get cookier proxy_aws_creds
			b64Creds, err := r.Cookie("proxy_aws_creds")
			if err != nil || b64Creds.Value == "" {
				log.Printf("failed to get cookie proxy_aws_creds: %s", err)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			// Extract creds from cookie
			decodedCreds, err := base64.StdEncoding.DecodeString(b64Creds.Value)
			if err != nil {
				log.Printf("failed to decode cookie proxy_aws_creds: %s", err)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			var creds provider.AWSCreds
			err = json.Unmarshal(decodedCreds, &creds)
			if err != nil {
				log.Printf("failed to unmarshal cookie proxy_aws_creds: %s", err)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}

			// Try to refresh token with existing creds
			newToken, err := authProvider.Token(creds)
			if err != nil {
				log.Printf("failed to refresh token: %s", err)
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			token = newToken

			// As stated by RFC, cookie size limit must be at least 4096 bytes
			// so we split the token below this size to be compatible with all
			// browsers https://stackoverflow.com/a/52492934
			setTokenCookie(w, token, 4000)

		case *provider.ProviderTanzu:

			// Check if token is valid
			err = authProvider.Valid(token)
			if err == nil {
				break
			}

			log.Printf("failed to check if token is valid: %s", err)
			http.Redirect(w, r, "/login", http.StatusFound)
			return

		}

		// create the reverse proxy
		url, err := url.Parse(target)
		if err != nil {
			log.Printf("failed to parse target URL: %s", err)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		proxy := httputil.NewSingleHostReverseProxy(url)

		// add token as authorization header
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))

		// proxy request
		proxy.ServeHTTP(w, r)
	}
}
