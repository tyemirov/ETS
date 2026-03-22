package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"
)

func newReverseProxy(route upstreamRouteConfig) *httputil.ReverseProxy {
	reverseProxy := httputil.NewSingleHostReverseProxy(route.UpstreamBaseURL)
	originalDirector := reverseProxy.Director
	reverseProxy.Director = func(incomingRequest *http.Request) {
		originalDirector(incomingRequest)
		applyUpstreamCredentials(incomingRequest, route.Credentials)
	}
	reverseProxy.ErrorHandler = func(httpResponseWriter http.ResponseWriter, httpRequest *http.Request, proxyError error) {
		log.Printf("reverse proxy error: %v", proxyError)
		httpErrorJSON(httpResponseWriter, http.StatusBadGateway, "upstream_error")
	}
	return reverseProxy
}

func applyUpstreamCredentials(incomingRequest *http.Request, credentials upstreamCredentials) {
	if len(credentials.QueryParameters) > 0 {
		queryValues := incomingRequest.URL.Query()
		for key, value := range credentials.QueryParameters {
			queryValues.Set(key, value)
		}
		incomingRequest.URL.RawQuery = queryValues.Encode()
	}
	for key, value := range credentials.HeaderValues {
		incomingRequest.Header.Set(key, value)
	}
	if credentials.BearerToken != "" {
		incomingRequest.Header.Set(headerAuthorization, "Bearer "+credentials.BearerToken)
	}
}

func newHTTPServer(gatewayConfig serverConfig) *http.Server {
	replayCacheStore := &replayStore{seen: make(map[string]int64)}
	rateLimiterWindow := &windowLimiter{
		windowEnd:    timeNow().Unix() + 60,
		counts:       make(map[string]int),
		perMinuteCap: gatewayConfig.RateLimitPerMinute,
	}

	httpServerMux := http.NewServeMux()
	AttachGatewaySdk(httpServerMux)
	httpServerMux.HandleFunc("/tvm/issue", func(httpResponseWriter http.ResponseWriter, httpRequest *http.Request) {
		handleTokenIssue(httpResponseWriter, httpRequest, gatewayConfig)
	})
	for _, route := range gatewayConfig.UpstreamRoutes {
		upstreamReverseProxy := newReverseProxy(route)
		handler := http.HandlerFunc(func(httpResponseWriter http.ResponseWriter, httpRequest *http.Request) {
			handleProtectedProxy(httpResponseWriter, httpRequest, gatewayConfig, replayCacheStore, rateLimiterWindow, upstreamReverseProxy)
		})
		registerProxyRoute(httpServerMux, route.PublicPath, handler)
	}
	httpServerMux.HandleFunc("/health", handleHealth)

	return &http.Server{
		Addr:              gatewayConfig.ListenAddress,
		Handler:           httpServerMux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
}

func registerProxyRoute(mux *http.ServeMux, publicPath string, handler http.Handler) {
	if publicPath == "/" {
		mux.Handle(publicPath, handler)
		return
	}
	mux.Handle(publicPath, handler)
	if !strings.HasSuffix(publicPath, "/") {
		mux.Handle(publicPath+"/", handler)
	}
}

// tiny indirection to ease testing (can be stubbed)
var timeNow = func() time.Time { return time.Now() }
