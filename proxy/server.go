package proxy

import (
	"net/http"

	"github.com/go-chi/chi"
	"github.com/go-chi/chi/middleware"
)

func Server(loginURL, guestClusterName, proxyURL string) error {

	// Create router
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.Logger)

	// Register handlers
	r.HandleFunc("/*", proxyHandler(proxyURL))
	r.Get("/login", loginGetHandler)
	r.Post("/login", loginPostHandler(loginURL, guestClusterName))

	// Serve requests
	return http.ListenAndServe(":8080", r)
}
