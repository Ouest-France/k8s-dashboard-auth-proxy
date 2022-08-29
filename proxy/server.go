package proxy

import (
	"log"
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func Server(loginURL, guestClusterName, proxyURL string, debug bool) error {

	// Remove timestamp from logs
	log.SetFlags(0)

	// Create router
	r := chi.NewRouter()

	// Enable request logging if debug is enabled
	if debug {
		r.Use(middleware.Logger)
	}

	// Add routes
	r.HandleFunc("/*", proxyHandler(proxyURL))
	r.Get("/login", loginGetHandler)
	r.Post("/login", loginPostHandler(loginURL, guestClusterName))
	r.Get("/logout", logoutGetHandler)

	// Serve requests
	return http.ListenAndServe(":8080", r)
}
