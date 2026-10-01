package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestNewReverseProxy_AppendsSecretWhenMissing(t *testing.T) {
	upstreamURL, parseErr := url.Parse("http://upstream.example:8080")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}
	route := newTestRoute(upstreamURL, "/api")
	route.Credentials.QueryParameters["key"] = "super-secret"

	reverseProxy := newReverseProxy(route)
	request, requestErr := http.NewRequest(http.MethodGet, "http://ets.example/api?prompt=hi", nil)
	if requestErr != nil {
		t.Fatalf("http.NewRequest: %v", requestErr)
	}

	reverseProxy.Director(request)

	query := request.URL.Query()
	if query.Get("key") != "super-secret" {
		t.Fatalf("expected injected key query parameter")
	}
	if query.Get("prompt") != "hi" {
		t.Fatalf("expected existing query parameters to remain")
	}
}

func TestNewReverseProxy_OverridesExistingSecret(t *testing.T) {
	upstreamURL, parseErr := url.Parse("http://upstream.example:8080")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}
	route := newTestRoute(upstreamURL, "/api")
	route.Credentials.QueryParameters["key"] = "super-secret"

	reverseProxy := newReverseProxy(route)
	request, requestErr := http.NewRequest(http.MethodGet, "http://ets.example/api?prompt=hi&key=user", nil)
	if requestErr != nil {
		t.Fatalf("http.NewRequest: %v", requestErr)
	}

	reverseProxy.Director(request)
	if request.URL.Query().Get("key") != "super-secret" {
		t.Fatalf("expected injected key to override existing value")
	}
}

func TestNewReverseProxy_AppliesHeadersAndBearerToken(t *testing.T) {
	upstreamURL, parseErr := url.Parse("https://upstream.example")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}
	route := newTestRoute(upstreamURL, "/api")
	route.Credentials.HeaderValues["X-Upstream-Tenant"] = "demo"
	route.Credentials.BearerToken = "abc123"

	reverseProxy := newReverseProxy(route)
	request := httptest.NewRequest(http.MethodGet, "http://ets.example/api", nil)
	request.Header.Set(headerAuthorization, "Bearer client-token")

	reverseProxy.Director(request)
	if request.Header.Get("X-Upstream-Tenant") != "demo" {
		t.Fatalf("expected configured header to be applied")
	}
	if request.Header.Get(headerAuthorization) != "Bearer abc123" {
		t.Fatalf("expected bearer token to override Authorization header")
	}
}

func TestNewHTTPServer_RoutesApiSubpaths(t *testing.T) {
	upstreamURL, parseErr := url.Parse("http://upstream.example:8080")
	if parseErr != nil {
		t.Fatalf("url.Parse: %v", parseErr)
	}

	config := serverConfig{
		ListenAddress:      ":8080",
		AllowedOrigins:     map[string]struct{}{"https://app.example.com": {}},
		TokenLifetime:      5 * time.Minute,
		JwtHmacKey:         []byte("0123456789abcdef0123456789abcdef"),
		UpstreamRoutes: []upstreamRouteConfig{
			newTestRoute(upstreamURL, "/api"),
		},
		RateLimitPerMinute: 60,
		UpstreamTimeout:    10 * time.Second,
	}

	httpServer := newHTTPServer(config)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://ets.example/api/search", strings.NewReader(`{"prompt":"hi"}`))
	request.Header.Set("Origin", "https://app.example.com")

	httpServer.Handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected /api/subpath to reach proxy handler and return 401 for missing bearer, got %d", recorder.Code)
	}
}

func TestNewHTTPServer_RegistersMultiplePublicPaths(t *testing.T) {
	primaryURL, err := url.Parse("http://upstream-primary")
	if err != nil {
		t.Fatalf("url.Parse primary: %v", err)
	}
	secondaryURL, err := url.Parse("http://upstream-secondary")
	if err != nil {
		t.Fatalf("url.Parse secondary: %v", err)
	}

	config := serverConfig{
		ListenAddress:      ":8080",
		AllowedOrigins:     map[string]struct{}{"https://app.example.com": {}},
		TokenLifetime:      5 * time.Minute,
		JwtHmacKey:         []byte("fedcba9876543210fedcba9876543210"),
		UpstreamRoutes: []upstreamRouteConfig{
			newTestRoute(primaryURL, "/api"),
			newTestRoute(secondaryURL, "/tiles"),
		},
		RateLimitPerMinute: 60,
		UpstreamTimeout:    10 * time.Second,
	}

	httpServer := newHTTPServer(config)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "http://ets.example/tiles/info", strings.NewReader(`{"prompt":"hi"}`))
	request.Header.Set("Origin", "https://app.example.com")

	httpServer.Handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected /tiles to be registered and return 401 for missing bearer, got %d", recorder.Code)
	}
}

func newTestRoute(upstreamURL *url.URL, publicPath string) upstreamRouteConfig {
	return upstreamRouteConfig{
		PublicPath:      publicPath,
		UpstreamBaseURL: upstreamURL,
		Credentials: upstreamCredentials{
			HeaderValues:    make(map[string]string),
			QueryParameters: make(map[string]string),
		},
	}
}
