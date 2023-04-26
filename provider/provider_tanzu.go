package provider

import (
	"fmt"
	"net/url"
)

type ProviderTanzu struct {
	LoginURL     string
	GuestCluster string
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
	return "", nil
}

// Valid is used to check if a token is valid
func (p *ProviderTanzu) Valid(token string) (err error) {
	return nil
}
