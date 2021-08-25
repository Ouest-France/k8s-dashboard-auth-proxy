package proxy

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
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
	http.SetCookie(w, &http.Cookie{Name: "proxy_auth_token_parts", Value: fmt.Sprint(len(splittedToken))})

	// We store each token parts in a separate cookie with name proxy_auth_token_X
	for partIndex, partValue := range splittedToken {
		http.SetCookie(w, &http.Cookie{Name: fmt.Sprintf("proxy_auth_token_%d", partIndex), Value: partValue})
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

	// // Check if token expired
	// expired, err := tokenExpired(token)
	// if err != nil {
	// 	return "", fmt.Errorf("failed to check if token expired: %s", err)
	// }
	// if expired {
	// 	return "", errors.New("token expired")
	// }

	return token, nil
}

// tokenExpired checks if JWT token is expired
func tokenExpired(rawToken string) (bool, error) {
	// Split Header/Payload/Signature parts of JWT token
	jwtTokenSlice := strings.Split(rawToken, ".")
	if len(jwtTokenSlice) != 3 {
		return false, fmt.Errorf("JWT token is in %d parts but must be in 3 parts", len(jwtTokenSlice))
	}
	jwtPayloadJSONBase64 := jwtTokenSlice[1]

	// Decode Base64 encoded payload part
	jwtPayloadJSON, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(jwtPayloadJSONBase64)
	if err != nil {
		return false, fmt.Errorf("failed to decode token base64 payload: %s", err)
	}

	// Decode JSON payload
	var jwtPayload JWTPayload
	err = json.Unmarshal([]byte(jwtPayloadJSON), &jwtPayload)
	if err != nil {
		return false, fmt.Errorf("failed to unmarshald token json payload: %s", err)
	}

	// Return true if current timestamp is after JWT expire timestamp
	return time.Now().After(time.Unix(jwtPayload.Exp, 0)), nil
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

// margeToken merges tokens parts
func mergeToken(tokenParts []string) string {
	token := ""
	for _, tokenPart := range tokenParts {
		token = token + tokenPart
	}

	return token
}
