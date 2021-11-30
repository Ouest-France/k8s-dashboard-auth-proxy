package proxy

import (
	_ "embed" //embed web resources for login page
	"fmt"
	"net/http"
)

// logoutGetHandler delete auth cookies
func logoutGetHandler(w http.ResponseWriter, r *http.Request) {

	// Call token cookie deletion helper
	err := deleteTokenCookie(w, r)
	if err != nil {
		fmt.Printf("deleting token cookie: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}
