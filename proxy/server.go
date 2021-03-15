package proxy

import (
	"log"
	"net/http"

	"github.com/go-chi/chi"
)

func Server(loginURL, guestClusterName, proxyURL string) error {

	// Remove timestamp from logs
	log.SetFlags(0)

	// Create router and register handlers
	r := chi.NewRouter()
	r.HandleFunc("/*", proxyHandler(proxyURL))
	r.Get("/login", loginGetHandler)
	r.Post("/login", loginPostHandler(loginURL, guestClusterName))

	// Serve requests
	return http.ListenAndServe(":8080", r)
}
