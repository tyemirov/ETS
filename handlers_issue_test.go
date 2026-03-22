package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestHandleTokenIssue_PostsJwtWithValidDpop(t *testing.T) {
	upstreamURL, parseErr := url.Parse("http://upstream.example")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}

	gatewayConfig := serverConfig{
		AllowedOrigins:     map[string]struct{}{"https://app.example.com": {}},
		TokenLifetime:      5 * time.Minute,
		JwtHmacKey:         []byte("0123456789abcdef0123456789abcdef"),
		UpstreamRoutes:     []upstreamRouteConfig{newTestRoute(upstreamURL, "/api")},
		RateLimitPerMinute: 100,
		UpstreamTimeout:    10 * time.Second,
	}

	dpopKey, keyErr := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if keyErr != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", keyErr)
	}
	publicKey := dpopKey.PublicKey
	publicJwk := publicJwk{
		KeyType: "EC",
		Curve:   "P-256",
		X:       base64.RawURLEncoding.EncodeToString(publicKey.X.Bytes()),
		Y:       base64.RawURLEncoding.EncodeToString(publicKey.Y.Bytes()),
	}

	bodyBytes, marshalErr := json.Marshal(tokenIssueRequest{DpopPublicJwk: publicJwk})
	if marshalErr != nil {
		t.Fatalf("json.Marshal: %v", marshalErr)
	}

	request := httptest.NewRequest(http.MethodPost, "http://ets.example/tvm/issue", bytes.NewReader(bodyBytes))
	request.Header.Set("Origin", "https://app.example.com")

	recorder := httptest.NewRecorder()
	handleTokenIssue(recorder, request, gatewayConfig)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recorder.Code)
	}

	var response tokenIssueResponse
	if decodeErr := json.NewDecoder(recorder.Body).Decode(&response); decodeErr != nil {
		t.Fatalf("Decode response: %v", decodeErr)
	}
	if response.AccessToken == "" || response.ExpiresIn == 0 {
		t.Fatalf("expected non-empty token response: %+v", response)
	}
}

func TestHandleTokenIssue_RejectsNonPost(t *testing.T) {
	upstreamURL, parseErr := url.Parse("http://upstream.example")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}

	gatewayConfig := serverConfig{
		AllowedOrigins:     map[string]struct{}{"https://app.example.com": {}},
		TokenLifetime:      5 * time.Minute,
		JwtHmacKey:         []byte("abcdef0123456789abcdef0123456789"),
		UpstreamRoutes:     []upstreamRouteConfig{newTestRoute(upstreamURL, "/api")},
		RateLimitPerMinute: 100,
		UpstreamTimeout:    10 * time.Second,
	}

	request := httptest.NewRequest(http.MethodGet, "http://ets.example/tvm/issue", nil)
	request.Header.Set("Origin", "https://app.example.com")
	recorder := httptest.NewRecorder()

	handleTokenIssue(recorder, request, gatewayConfig)
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", recorder.Code)
	}
}
