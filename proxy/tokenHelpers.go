package proxy

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
)

// JWTPayload represents tha payload part of the JWT token
type JWTPayload struct {
	Exp int64 `json:"exp"`
}

// setTokenCookie split token by cookieMaxSize and store it as cookies
func setTokenCookie(w http.ResponseWriter, token string, cookieMaxSize int) {
	// Split token by cookieMaxSize
	splittedToken := splitToken(token, cookieMaxSize)

	// We store the number of token parts in proxy_auth_token_parts cookie
	http.SetCookie(w, &http.Cookie{Name: "proxy_auth_token_parts", Value: fmt.Sprint(len(splittedToken)), Path: "/"})

	// We store each token parts in a separate cookie with name proxy_auth_token_X
	for partIndex, partValue := range splittedToken {
		http.SetCookie(w, &http.Cookie{Name: fmt.Sprintf("proxy_auth_token_%d", partIndex), Value: partValue, Path: "/"})
	}
}

// getTokenCookie merge token cookies and return it
func getTokenCookie(r *http.Request) (string, error) {
	// Read number of parts cookie from request
	tokenPartsCookie, err := r.Cookie("proxy_auth_token_parts")
	if err != nil || tokenPartsCookie.Value == "" {
		return "", errors.New("token proxy_auth_token_parts doesn't exists or is empty")
	}
	parts, err := strconv.Atoi(tokenPartsCookie.Value)
	if err != nil {
		return "", fmt.Errorf("failed to parse int from token proxy_auth_token_parts cookie: %w", err)
	}

	// Merge data cookies from request
	token := ""
	for i := 0; i < parts; i++ {
		tokenPartCookie, err := r.Cookie(fmt.Sprintf("proxy_auth_token_%d", i))
		if err != nil || tokenPartCookie.Value == "" {
			return "", fmt.Errorf("token proxy_auth_token_%d doesn't exists or is empty", i)
		}
		token = token + tokenPartCookie.Value
	}

	return token, nil
}

func deleteTokenCookie(w http.ResponseWriter, r *http.Request) error {

	// Delete proxy_auth_token_parts cookie
	http.SetCookie(w, &http.Cookie{Name: "proxy_auth_token_parts", Value: "", MaxAge: 0, Path: "/"})

	// Compile regex to extract token parts cookies
	cookieRegex, err := regexp.Compile("proxy_auth_token_.*")
	if err != nil {
		return fmt.Errorf("compiling proxy auth token regex: %s", err)
	}

	// List token parts cookies
	for _, cookie := range r.Cookies() {
		if cookieRegex.MatchString(cookie.Name) {
			http.SetCookie(w, &http.Cookie{Name: cookie.Name, Value: "", MaxAge: -1, Path: "/"})
		}
	}

	// Delete cookie proxy_aws_creds
	http.SetCookie(w, &http.Cookie{
		Name:   "proxy_aws_creds",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	return nil
}

// splitToken splits a token by size
func splitToken(token string, size int) []string {
	parts := []string{}
	current := 0
	for {
		if len(token[current:]) > size {
			parts = append(parts, token[current:current+size])
			current = current + size
			continue
		}

		parts = append(parts, token[current:])
		break
	}

	return parts
}
