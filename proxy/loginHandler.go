package proxy

import (
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

//go:embed embed/login.html
var loginPage []byte

// TanzuAuthResult represents the JSON response from Tanzu Auth
type TanzuAuthResult struct {
	SessionID string `json:"session_id"`
}

// loginGetHandler displays the login form
func loginGetHandler(w http.ResponseWriter, r *http.Request) {
	_, err := w.Write(loginPage)
	if err != nil {
		fmt.Printf("failed to write login page: %s", err)
	}
}

// loginPostHandler handles the Tanzu authentication logic
func loginPostHandler(loginURL, guestClusterName string) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// Get user and password from posted form
		username := r.FormValue("username")
		password := r.FormValue("password")

		// Check that username and password are defined
		if username == "" || password == "" {
			fmt.Println("username or password empty")
			http.Redirect(w, r, "/login", 302)
			return
		}

		// Create HTTP client for auth request
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

		// Create JSON payload
		payload := fmt.Sprintf("{\"guest_cluster_name\":\"%s\"}", guestClusterName)

		// Create login request
		req, err := http.NewRequest("POST", loginURL, strings.NewReader(payload))
		if err != nil {
			fmt.Printf("failed to create login request: %s\n", err)
			http.Redirect(w, r, "/login", 302)
			return
		}

		// Add JSON content type
		req.Header.Add("Content-Type", "application/json")

		// Add username and password as basicauth
		req.SetBasicAuth(username, password)

		// Send login request
		resp, err := client.Do(req)
		if err != nil {
			fmt.Printf("login request failed: %s\n", err)
			http.Redirect(w, r, "/login", 302)
			return
		}
		defer resp.Body.Close()

		// Read JSON response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			fmt.Printf("failed to read login response body: %s\n", err)
			http.Redirect(w, r, "/login", 302)
			return
		}
		var TanzuAuthResult TanzuAuthResult
		err = json.Unmarshal(body, &TanzuAuthResult)
		if err != nil {
			fmt.Printf("failed to unmarshal json login response: %s\n", err)
			http.Redirect(w, r, "/login", 302)
			return
		}

		err = setTokenCookie(w, TanzuAuthResult.SessionID)
		if err != nil {
			fmt.Printf("failed to set token cookie: %s\n", err)
			http.Redirect(w, r, "/login", 302)
			return
		}

		http.Redirect(w, r, "/", 302)
	}
}
