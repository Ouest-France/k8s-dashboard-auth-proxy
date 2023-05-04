package proxy

import (
	_ "embed" //embed web resources for login page
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"

	"github.com/Ouest-France/k8s-dashboard-auth-proxy/provider"
)

//go:embed embed/login.html.tmpl
var loginPageTemplate string

//go:embed embed/role.html.tmpl
var rolePageTemplate string

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
		log.Printf("failed to parse login page template: %v", err)
		return
	}

	// Execute template with login error if provided in URL
	err = tmpl.ExecuteTemplate(w, "login", loginErrorMessage)
	if err != nil {
		log.Printf("failed to execute login page template: %v", err)
		return
	}
}

// loginPostHandler handles the Tanzu authentication logic
func loginPostHandler(authProvider provider.Provider) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// Switch on auth provider
		switch authProvider := authProvider.(type) {
		case *provider.ProviderAwsAdfs:

			switch r.FormValue("step") {
			case "login":
				adfsProvider := authProvider

				// Check if username and password are provided
				username := r.FormValue("username")
				password := r.FormValue("password")

				if username == "" || password == "" {
					log.Printf("username or password not provided")
					http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Username or password not provided")), http.StatusFound)
					return
				}

				// Authenticate user
				assertion, roles, err := adfsProvider.Login(username, password)
				if err != nil {
					log.Printf("failed to authenticate user: %v", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Authentication failed")), http.StatusFound)
					return
				}

				// Parse role template
				tmpl, err := template.New("role").Parse(rolePageTemplate)
				if err != nil {
					log.Printf("failed to parse role page template: %v", err)
					return
				}

				// Execute template with role error if provided in URL
				err = tmpl.ExecuteTemplate(w, "role", struct {
					Assertion string
					Roles     map[string]string
				}{
					Assertion: assertion,
					Roles:     roles,
				})
				if err != nil {
					log.Printf("failed to execute role page template: %v", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Failed to execute role page template")), http.StatusFound)
					return
				}
			case "role":
				adfsProvider := authProvider

				// Check if role is provided
				role := r.FormValue("role")
				if role == "" {
					log.Printf("role not provided")
					http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Role not provided")), http.StatusFound)
					return
				}

				// Check if assertion is provided
				assertion := r.FormValue("assertion")
				if assertion == "" {
					log.Printf("assertion not provided")
					http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Assertion not provided")), http.StatusFound)
					return
				}

				// Assume role with SAML assertion
				creds, err := adfsProvider.AssumeRole(assertion, role)
				if err != nil {
					log.Printf("failed to assume role: %v", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Failed to assume role")), http.StatusFound)
					return
				}

				// Marshal credentials to base64 encoded JSON and store them in proxy_aws_creds cookie
				jsonCreds, err := json.Marshal(creds)
				if err != nil {
					log.Printf("failed to marshal credentials: %v", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Failed to marshal credentials")), http.StatusFound)
					return
				}
				b64JsonCreds := base64.StdEncoding.EncodeToString(jsonCreds)
				http.SetCookie(w, &http.Cookie{Name: "proxy_aws_creds", Value: b64JsonCreds, MaxAge: 36000})

				// Get token from credentials
				token, err := adfsProvider.Token(creds)
				if err != nil {
					log.Printf("failed to get token: %v", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Failed to get token")), http.StatusFound)
					return
				}

				// As stated by RFC, cookie size limit must be at least 4096 bytes
				// so we split the token below this size to be compatible with all
				// browsers https://stackoverflow.com/a/52492934
				setTokenCookie(w, token, 4000)

				http.Redirect(w, r, "/", http.StatusFound)
			}

		case *provider.ProviderTanzu:

			// Check if username and password are provided
			username := r.FormValue("username")
			password := r.FormValue("password")

			if username == "" || password == "" {
				log.Printf("username or password not provided")
				http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Username or password not provided")), http.StatusFound)
				return
			}

			// Authenticate user
			tanzuProvider := authProvider
			token, err := tanzuProvider.Login(username, password)
			if err != nil {
				log.Printf("failed to authenticate user: %v", err)
				http.Redirect(w, r, fmt.Sprintf("/login?error=%v", url.QueryEscape("Authentication failed")), http.StatusFound)
				return
			}

			// As stated by RFC, cookie size limit must be at least 4096 bytes
			// so we split the token below this size to be compatible with all
			// browsers https://stackoverflow.com/a/52492934
			setTokenCookie(w, token, 4000)

			http.Redirect(w, r, "/", http.StatusFound)
		}
	}
}
