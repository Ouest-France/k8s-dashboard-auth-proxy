package provider

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type ProviderTanzu struct {
	LoginURL     string
	GuestCluster string
}

// JWTPayload represents tha payload part of the JWT token
type JWTPayload struct {
	Exp int64 `json:"exp"`
}

// TanzuAuthResult represents the JSON response from Tanzu Auth
type TanzuAuthResult struct {
	SessionID string `json:"session_id"`
}

func NewProviderTanzu(loginURL string, guestCluster string) (*ProviderTanzu, error) {

	// Check if login URL is valid
	if loginURL == "" {
		return nil, fmt.Errorf("login URL must be set")
	}
	_, err := url.ParseRequestURI(loginURL)
	if err != nil {
		return nil, fmt.Errorf("invalid login URL: %w", err)
	}

	// Check if guest cluster is valid
	if guestCluster == "" {
		return nil, fmt.Errorf("guest cluster must be set")
	}

	return &ProviderTanzu{
		LoginURL:     loginURL,
		GuestCluster: guestCluster,
	}, nil
}

// Login is used to do the Tanzu login
func (p *ProviderTanzu) Login(user, password string) (string, error) {

	// Create HTTP client for auth request
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}

	// Create JSON payload
	payloadStruct := struct {
		GuestClusterName string `json:"guest_cluster_name"`
	}{
		GuestClusterName: p.GuestCluster,
	}
	payload, err := json.Marshal(payloadStruct)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create login request
	req, err := http.NewRequest("POST", p.LoginURL, strings.NewReader(string(payload)))
	if err != nil {
		return "", fmt.Errorf("failed to create login request: %w", err)
	}

	// Add JSON content type
	req.Header.Add("Content-Type", "application/json")

	// Add username and password as basicauth
	req.SetBasicAuth(user, password)

	// Send login request
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send login request: %w", err)
	}
	defer resp.Body.Close()

	// Check HTTP code for login succeeded
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login failed with HTTP code %d", resp.StatusCode)
	}

	// Read JSON response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read login response: %w", err)
	}
	var TanzuAuthResult TanzuAuthResult
	err = json.Unmarshal(body, &TanzuAuthResult)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal login response: %w", err)
	}

	return TanzuAuthResult.SessionID, nil
}

// Valid is used to check if a token is valid
func (p *ProviderTanzu) Valid(token string) (err error) {

	// Split Header/Payload/Signature parts of JWT token
	jwtTokenSlice := strings.Split(token, ".")
	if len(jwtTokenSlice) != 3 {
		return fmt.Errorf("JWT token is in %d parts but must be in 3 parts", len(jwtTokenSlice))
	}
	jwtPayloadJSONBase64 := jwtTokenSlice[1]

	// Decode Base64 encoded payload part
	jwtPayloadJSON, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(jwtPayloadJSONBase64)
	if err != nil {
		return fmt.Errorf("failed to decode token base64 payload: %s", err)
	}

	// Decode JSON payload
	var jwtPayload JWTPayload
	err = json.Unmarshal([]byte(jwtPayloadJSON), &jwtPayload)
	if err != nil {
		return fmt.Errorf("failed to unmarshald token json payload: %s", err)
	}

	// Return true if current timestamp is after JWT expire timestamp
	if time.Now().After(time.Unix(jwtPayload.Exp, 0)) {
		return fmt.Errorf("token is expired")
	}

	return nil
}
