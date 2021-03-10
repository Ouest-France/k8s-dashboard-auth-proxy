package proxy

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
)

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
		fmt.Printf("failed to decode base64 token: %s\n", err)
		return "", err
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
