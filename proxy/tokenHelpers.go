package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// JWTPayload represents tha payload part of the JWT token
type JWTPayload struct {
	Exp int64 `json:"exp"`
}

// setTokenCookie compress token and set it as cookie
func setTokenCookie(w http.ResponseWriter, token string) error {
	compressedToken, err := compressToken(token)
	if err != nil {
		return fmt.Errorf("failed to compress token: %s", err)
	}
	http.SetCookie(w, &http.Cookie{Name: "proxy_auth_token_gz", Value: compressedToken})

	return nil
}

// getTokenCookie uncompress token and return it
func getTokenCookie(r *http.Request) (string, error) {
	// Read cookie from request
	tokenCookie, err := r.Cookie("proxy_auth_token_gz")
	if err != nil || tokenCookie.Value == "" {
		return "", errors.New("token proxy_auth_token_gz doesn't exists or is empty")
	}
	compressedToken := tokenCookie.Value

	// Uncompress cookie
	token, err := uncompressToken(compressedToken)
	if err != nil {
		return "", fmt.Errorf("failed to uncompress token: %s", err)
	}

	// Check token is not empty
	if token == "" {
		return "", errors.New("token is empty")
	}

	// Check if token expired
	expired, err := tokenExpired(token)
	if err != nil {
		return "", fmt.Errorf("failed to check if token expired: %s", err)
	}
	if expired {
		return "", errors.New("token expired")
	}

	return token, nil
}

// compressToken gzip and base64 encode a token
func compressToken(token string) (string, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	_, err = zw.Write([]byte(token))
	if err != nil {
		return "", err
	}
	err = zw.Close()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// uncompressToken base64 decode and ungzip a token
func uncompressToken(b64Token string) (string, error) {
	token, err := base64.StdEncoding.DecodeString(b64Token)
	if err != nil {
		return "", fmt.Errorf("failed to decode base64 token: %s", err)
	}

	zr, err := gzip.NewReader(bytes.NewBuffer(token))
	if err != nil {
		return "", fmt.Errorf("failed to uncompress token: %s", err)
	}
	tokenBytes, err := io.ReadAll(zr)
	if err != nil {
		return "", err
	}

	return string(tokenBytes), nil
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
