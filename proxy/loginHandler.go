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

//go:embed embed/login_error.html.tmpl
var loginErrorPageTemplate string

//go:embed embed/role.html.tmpl
var rolePageTemplate string

// loginGetHandler displays the login form
func loginGetHandler(authProvider provider.Provider) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// Switch on auth provider
		switch authProvider := authProvider.(type) {
		case *provider.ProviderAwsAdfs:

			// Retrieve login error message from URL
			var loginErrorMessage string
			queryLoginError, ok := r.URL.Query()["error"]
			if ok && len(queryLoginError) == 1 {
				loginErrorMessage = queryLoginError[0]
			}
			if loginErrorMessage != "" {
				// Parse login template
				tmpl, err := template.New("login_error").Parse(loginErrorPageTemplate)
				if err != nil {
					log.Printf("failed to parse login_error page template: %s", err)
					return
				}

				// Execute template with login error if provided in URL
				err = tmpl.ExecuteTemplate(w, "login_error", loginErrorMessage)
				if err != nil {
					log.Printf("failed to execute login_error page template: %s", err)
					return
				}

				return
			}

			// Create SAML request
			samlURL, err := authProvider.Login()
			if err != nil {
				log.Printf("failed to create SAML request: %s", err)
				return
			}

			// Redirect to SAML provider
			http.Redirect(w, r, samlURL, http.StatusFound)

		case *provider.ProviderTanzu:

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
	}
}

// loginPostHandler handles the Tanzu authentication logic
func loginPostHandler(authProvider provider.Provider) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {

		// Switch on auth provider
		switch authProvider := authProvider.(type) {
		case *provider.ProviderAwsAdfs:

			// Get step as URL parameter
			params, err := url.ParseQuery(r.URL.RawQuery)
			if err != nil {
				log.Printf("failed to parse query: %s", err)
				http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Failed to parse query")), http.StatusFound)
				return
			}

			switch params.Get("step") {
			case "saml":

				// Check if SAML response is provided
				samlResponse := r.FormValue("SAMLResponse")
				if samlResponse == "" {
					log.Printf("SAML response not provided")
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("SAML response not provided")), http.StatusFound)
					return
				}

				// Process SAML response
				samlResponse, roles, err := authProvider.SAML(samlResponse)
				if err != nil {
					log.Printf("failed to process SAML response: %s", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Authentication failed")), http.StatusFound)
					return
				}

				// Parse role template
				tmpl, err := template.New("role").Parse(rolePageTemplate)
				if err != nil {
					log.Printf("failed to parse role page template: %s", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Failed to parse role page template")), http.StatusFound)
					return
				}

				// Execute template with role error if provided in URL
				err = tmpl.ExecuteTemplate(w, "role", struct {
					Assertion string
					Roles     map[string]string
				}{
					Assertion: samlResponse,
					Roles:     roles,
				})
				if err != nil {
					log.Printf("failed to execute role page template: %s", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Failed to execute role page template")), http.StatusFound)
					return
				}
			case "role":

				// Check if role is provided
				role := r.FormValue("role")
				if role == "" {
					log.Printf("role not provided")
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Role not provided")), http.StatusFound)
					return
				}

				// Check if assertion is provided
				assertion := r.FormValue("assertion")
				if assertion == "" {
					log.Printf("assertion not provided")
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Assertion not provided")), http.StatusFound)
					return
				}

				// Assume role with SAML assertion
				creds, err := authProvider.AssumeRole(assertion, role)
				if err != nil {
					log.Printf("failed to assume role: %s", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Failed to assume role")), http.StatusFound)
					return
				}

				// Marshal credentials to base64 encoded JSON and store them in proxy_aws_creds cookie
				jsonCreds, err := json.Marshal(creds)
				if err != nil {
					log.Printf("failed to marshal credentials: %s", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Failed to marshal credentials")), http.StatusFound)
					return
				}
				b64JsonCreds := base64.StdEncoding.EncodeToString(jsonCreds)
				http.SetCookie(w, &http.Cookie{Name: "proxy_aws_creds", Value: b64JsonCreds})

				// Get token from credentials
				token, err := authProvider.Token(creds)
				if err != nil {
					log.Printf("failed to get token: %s", err)
					http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Failed to get token")), http.StatusFound)
					return
				}

				// As stated by RFC, cookie size limit must be at least 4096 bytes
				// so we split the token below this size to be compatible with all
				// browsers https://stackoverflow.com/a/52492934
				setTokenCookie(w, token, 4000)

				http.Redirect(w, r, "/", http.StatusFound)
			default:

				log.Printf("step not provided")
				http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Step not provided")), http.StatusFound)
				return
			}

		case *provider.ProviderTanzu:

			// Check if username and password are provided
			username := r.FormValue("username")
			password := r.FormValue("password")

			if username == "" || password == "" {
				log.Printf("username or password not provided")
				http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Username or password not provided")), http.StatusFound)
				return
			}

			// Authenticate user
			tanzuProvider := authProvider
			token, err := tanzuProvider.Login(username, password)
			if err != nil {
				log.Printf("failed to authenticate user: %s", err)
				http.Redirect(w, r, fmt.Sprintf("/login?error=%s", url.QueryEscape("Authentication failed")), http.StatusFound)
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
