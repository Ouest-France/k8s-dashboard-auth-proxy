package proxy

import (
	"log"
	"net/http"

	"github.com/Ouest-France/k8s-dashboard-auth-proxy/provider"
	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func Server(proxyURL string, authProvider provider.Provider, debug bool) error {

	// Remove timestamp from logs
	log.SetFlags(0)

	// Create router
	r := chi.NewRouter()

	// Enable request logging if debug is enabled
	if debug {
		r.Use(middleware.Logger)
	}

	// Add routes
	r.HandleFunc("/*", proxyHandler(proxyURL, authProvider))
	r.Get("/login", loginGetHandler(authProvider))
	r.Post("/login", loginPostHandler(authProvider))
	r.Get("/logout", logoutGetHandler)

	//

	// Serve requests
	log.Printf("starting server on port https://0.0.0.0:8080")
	return http.ListenAndServeTLS(":8080", "localhost.crt", "localhost.key", r)
}
