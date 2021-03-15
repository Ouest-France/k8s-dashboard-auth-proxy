package proxy

import (
	"crypto/tls"
	_ "embed" //embed web resources for login page
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
)

//go:embed embed/login.html.tmpl
var loginPageTemplate string

// TanzuAuthResult represents the JSON response from Tanzu Auth
type TanzuAuthResult struct {
	SessionID string `json:"session_id"`
}

// loginGetHandler displays the login form
func loginGetHandler(w http.ResponseWriter, r *http.Request) {

	// Retrieve login error message from URL
	var loginErrorMessage string
	queryLoginError, ok := r.URL.Query()["error"]
	if ok && len(queryLoginError) == 1 {
		loginErrorMessage = queryLoginError[0]
	}

	// Parse login template
	tmpl, err := template.New("login").Parse(loginPageTemplate)
	if err != nil {
		log.Printf("failed to parse login page template: %s", err)
		return
	}

	// Execute template with login error if provided in URL
	err = tmpl.ExecuteTemplate(w, "login", loginErrorMessage)
	if err != nil {
		log.Printf("failed to execute login page template: %s", err)
		return
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
			log.Printf("username or password empty")
			http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Username or password empty")), 302)
			return
		}

		// Create HTTP client for auth request
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

		// Create JSON payload
		payload := fmt.Sprintf("{\"guest_cluster_name\":\"%s\"}", guestClusterName)

		// Create login request
		req, err := http.NewRequest("POST", loginURL, strings.NewReader(payload))
		if err != nil {
			log.Printf("creating login request: %s", err)
			http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Server error")), 302)
			return
		}

		// Add JSON content type
		req.Header.Add("Content-Type", "application/json")

		// Add username and password as basicauth
		req.SetBasicAuth(username, password)

		// Send login request
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("login request failed: %s", err)
			http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Server error")), 302)
			return
		}
		defer resp.Body.Close()

		// Check HTTP code for login succeeded
		if resp.StatusCode != 200 {
			log.Printf("login failed with non 200 http code for login response body: %d", resp.StatusCode)
			http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Invalid credentials")), 302)
			return
		}

		// Read JSON response
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Printf("failed to read login response body: %s", err)
			http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Server error")), 302)
			return
		}
		var TanzuAuthResult TanzuAuthResult
		err = json.Unmarshal(body, &TanzuAuthResult)
		if err != nil {
			log.Printf("failed to unmarshal json login response: %s", err)
			http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Server error")), 302)
			return
		}

		err = setTokenCookie(w, TanzuAuthResult.SessionID)
		if err != nil {
			log.Printf("failed to set token cookie: %s", err)
			http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Server error")), 302)
			return
		}

		http.Redirect(w, r, "/", 302)
	}
}
