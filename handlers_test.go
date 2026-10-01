package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestHandleProtectedProxy_InvalidDpopDoesNotMarkReplayCache(t *testing.T) {
	upstreamURL, parseErr := url.Parse("http://upstream.example")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}

	tokenSigningKey := []byte("0123456789abcdef0123456789abcdef")
	tokenID := "test-token-id"

	gatewayConfig := serverConfig{
		AllowedOrigins:     map[string]struct{}{"https://app.example.com": {}},
		TokenLifetime:      5 * time.Minute,
		JwtHmacKey:         tokenSigningKey,
		UpstreamRoutes:     []upstreamRouteConfig{newTestRoute(upstreamURL, "/api")},
		RateLimitPerMinute: 100,
		UpstreamTimeout:    10 * time.Second,
	}

	replayCache := &replayStore{seen: make(map[string]int64)}
	rateLimiter := &windowLimiter{
		windowEnd:    time.Now().Unix() + 60,
		counts:       make(map[string]int),
		perMinuteCap: 100,
	}

	accessToken := issueTestAccessToken(t, tokenSigningKey, tokenID)

	request := httptest.NewRequest(http.MethodPost, "http://ets.example/api", strings.NewReader(`{"hello":"world"}`))
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Authorization", "Bearer "+accessToken)

	recorder := httptest.NewRecorder()

	handleProtectedProxy(recorder, request, gatewayConfig, replayCache, rateLimiter, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("expected upstream proxy to be skipped for invalid DPoP")
	}))

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized for missing DPoP, got %d", recorder.Code)
	}
	if _, exists := replayCache.seen[tokenID]; exists {
		t.Fatalf("replay cache should not be marked when DPoP validation fails")
	}
}

func TestHandleProtectedProxy_AllowsMultipleRequestsWithSameTokenAndDistinctDpop(t *testing.T) {
	upstreamURL, parseErr := url.Parse("http://upstream.example")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}

	tokenSigningKey := []byte("abcdef0123456789abcdef0123456789")
	tokenID := "token-multi-use"

	gatewayConfig := serverConfig{
		AllowedOrigins:     map[string]struct{}{"https://app.example.com": {}},
		TokenLifetime:      5 * time.Minute,
		JwtHmacKey:         tokenSigningKey,
		UpstreamRoutes:     []upstreamRouteConfig{newTestRoute(upstreamURL, "/api")},
		RateLimitPerMinute: 100,
		UpstreamTimeout:    10 * time.Second,
	}

	replayCache := &replayStore{seen: make(map[string]int64)}
	rateLimiter := &windowLimiter{
		windowEnd:    time.Now().Unix() + 60,
		counts:       make(map[string]int),
		perMinuteCap: 100,
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
	thumbprint, thumbErr := jwkThumbprint(publicJwk)
	if thumbErr != nil {
		t.Fatalf("jwkThumbprint: %v", thumbErr)
	}

	accessToken := issueTestAccessTokenWithThumbprint(t, tokenSigningKey, tokenID, thumbprint)

	upstreamCalls := 0
	upstreamProxy := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalls++
		writer.WriteHeader(http.StatusNoContent)
	})

	requestURL := "http://ets.example/api"
	var firstProof string
	for requestIndex := 0; requestIndex < 2; requestIndex++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, requestURL, strings.NewReader(`{"request":`+fmt.Sprint(requestIndex)+`}`))
		request.Header.Set("Origin", "https://app.example.com")
		request.Header.Set("Authorization", "Bearer "+accessToken)

		dpopProof := mustCreateDpopProof(t, dpopKey, publicJwk, http.MethodPost, requestURL, fmt.Sprintf("proof-%d", requestIndex), time.Now())
		if requestIndex == 0 {
			firstProof = dpopProof
		}
		request.Header.Set(headerDpop, dpopProof)

		handleProtectedProxy(recorder, request, gatewayConfig, replayCache, rateLimiter, upstreamProxy)
		if recorder.Code != http.StatusNoContent {
			t.Fatalf("iteration %d expected 204, got %d", requestIndex, recorder.Code)
		}
	}

	if upstreamCalls != 2 {
		t.Fatalf("expected upstream proxy to be invoked twice, got %d", upstreamCalls)
	}

	replayRecorder := httptest.NewRecorder()
	replayRequest := httptest.NewRequest(http.MethodPost, requestURL, strings.NewReader(`{"request":"replay"}`))
	replayRequest.Header.Set("Origin", "https://app.example.com")
	replayRequest.Header.Set("Authorization", "Bearer "+accessToken)
	replayRequest.Header.Set(headerDpop, firstProof)

	handleProtectedProxy(replayRecorder, replayRequest, gatewayConfig, replayCache, rateLimiter, upstreamProxy)
	if replayRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected reused DPoP proof to be rejected with 401, got %d", replayRecorder.Code)
	}
	if upstreamCalls != 2 {
		t.Fatalf("upstream proxy should not be invoked on replay, got %d calls", upstreamCalls)
	}
}

func TestHandleProtectedProxy_AllowsGetRequests(t *testing.T) {
	upstreamURL, parseErr := url.Parse("http://upstream.example")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}

	tokenSigningKey := []byte("abcdef0123456789abcdef0123456789")
	tokenID := "token-get-allowed"

	gatewayConfig := serverConfig{
		AllowedOrigins:     map[string]struct{}{"https://app.example.com": {}},
		TokenLifetime:      5 * time.Minute,
		JwtHmacKey:         tokenSigningKey,
		UpstreamRoutes:     []upstreamRouteConfig{newTestRoute(upstreamURL, "/api")},
		RateLimitPerMinute: 100,
		UpstreamTimeout:    10 * time.Second,
	}

	replayCache := &replayStore{seen: make(map[string]int64)}
	rateLimiter := &windowLimiter{
		windowEnd:    time.Now().Unix() + 60,
		counts:       make(map[string]int),
		perMinuteCap: 100,
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
	thumbprint, thumbErr := jwkThumbprint(publicJwk)
	if thumbErr != nil {
		t.Fatalf("jwkThumbprint: %v", thumbErr)
	}

	accessToken := issueTestAccessTokenWithThumbprint(t, tokenSigningKey, tokenID, thumbprint)

	upstreamCalled := false
	upstreamProxy := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamCalled = true
		if request.Method != http.MethodGet {
			t.Fatalf("expected upstream to receive GET, got %s", request.Method)
		}
		writer.WriteHeader(http.StatusNoContent)
	})

	requestURL := "http://ets.example/api?prompt=hello"
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, requestURL, nil)
	request.Header.Set("Origin", "https://app.example.com")
	request.Header.Set("Authorization", "Bearer "+accessToken)
	dpopProof := mustCreateDpopProof(t, dpopKey, publicJwk, http.MethodGet, requestURL, "proof-get", time.Now())
	request.Header.Set(headerDpop, dpopProof)

	handleProtectedProxy(recorder, request, gatewayConfig, replayCache, rateLimiter, upstreamProxy)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", recorder.Code)
	}
	if !upstreamCalled {
		t.Fatalf("expected upstream to be invoked for GET request")
	}
}

func TestHandleHealth_ReturnsOkWithoutAuth(t *testing.T) {
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://ets.example/health", nil)

	handleHealth(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", recorder.Code)
	}
	if strings.TrimSpace(recorder.Body.String()) != "{\"status\":\"ok\"}" {
		t.Fatalf("unexpected body: %s", recorder.Body.String())
	}
}
func issueTestAccessToken(t *testing.T, signingKey []byte, tokenID string) string {
	return issueTestAccessTokenWithThumbprint(t, signingKey, tokenID, "test-thumb")
}

func issueTestAccessTokenWithThumbprint(t *testing.T, signingKey []byte, tokenID string, thumbprint string) string {
	t.Helper()
	currentTime := time.Now()
	claims := accessClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Audience:  jwt.ClaimStrings{audienceApi},
			IssuedAt:  jwt.NewNumericDate(currentTime),
			NotBefore: jwt.NewNumericDate(currentTime.Add(-1 * time.Second)),
			ExpiresAt: jwt.NewNumericDate(currentTime.Add(5 * time.Minute)),
			ID:        tokenID,
		},
		Confirmation: confirmation{JwkThumbprint: thumbprint},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, signErr := token.SignedString(signingKey)
	if signErr != nil {
		t.Fatalf("token.SignedString: %v", signErr)
	}
	return signedToken
}

func mustCreateDpopProof(t *testing.T, privateKey *ecdsa.PrivateKey, jwk publicJwk, method string, requestURL string, jwtID string, issuedAt time.Time) string {
	t.Helper()

	payload := dpopPayload{
		HttpMethod: method,
		HttpUri:    requestURL,
		JwtID:      jwtID,
		IssuedAt:   issuedAt.Unix(),
	}
	header := dpopHeader{
		Type: "dpop+jwt",
		Alg:  "ES256",
		Jwk:  jwk,
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("json.Marshal header: %v", err)
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("json.Marshal payload: %v", err)
	}

	headerPart := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadPart := base64.RawURLEncoding.EncodeToString(payloadJSON)
	signingInput := headerPart + "." + payloadPart

	digest := sha256.Sum256([]byte(signingInput))
	rValue, sValue, signErr := ecdsa.Sign(rand.Reader, privateKey, digest[:])
	if signErr != nil {
		t.Fatalf("ecdsa.Sign: %v", signErr)
	}

	signature := make([]byte, 64)
	copy(signature[32-len(rValue.Bytes()):32], rValue.Bytes())
	copy(signature[64-len(sValue.Bytes()):], sValue.Bytes())

	signaturePart := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + signaturePart
}
