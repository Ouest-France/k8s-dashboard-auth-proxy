package proxy

import (
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

		// Check if token is valid
		err = authProvider.Valid(token)
		if err != nil {
			log.Printf("failed to check if token is valid: %s", err)
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		// create the reverse proxy
		url, _ := url.Parse(target)
		proxy := httputil.NewSingleHostReverseProxy(url)

		// add token as authorization header
		r.Header.Set("Authorization", fmt.Sprintf("Bearer %s", string(token)))

		// proxy request
		proxy.ServeHTTP(w, r)
	}
}
