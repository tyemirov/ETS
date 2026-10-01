package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	envKeyListenAddress          = "LISTEN_ADDR"
	envKeyOriginAllowlist        = "ORIGIN_ALLOWLIST"
	envKeyTokenLifetimeSeconds   = "TOKEN_LIFETIME_SECONDS"
	envKeyJwtHmacKey             = "TVM_JWT_HS256_KEY"
	envKeyUpstreamBaseURL        = "UPSTREAM_BASE_URL"
	envKeyUpstreamServiceSecret  = "UPSTREAM_SERVICE_SECRET"
	envKeyUpstreamRoutes         = "UPSTREAM_ROUTES"
	envKeyRateLimitPerMinute     = "RATE_LIMIT_PER_MINUTE"
	envKeyUpstreamTimeoutSeconds = "UPSTREAM_TIMEOUT_SECONDS"

	defaultListenAddress          = ":8080"
	defaultTokenLifetimeSeconds   = 300
	defaultRateLimitPerMinute     = 60
	defaultUpstreamTimeoutSeconds = 40
)

type serverConfig struct {
	ListenAddress      string
	AllowedOrigins     map[string]struct{}
	TokenLifetime      time.Duration
	JwtHmacKey         []byte
	UpstreamRoutes     []upstreamRouteConfig
	RateLimitPerMinute int
	UpstreamTimeout    time.Duration
}

type upstreamRouteConfig struct {
	PublicPath      string
	UpstreamBaseURL *url.URL
	Credentials     upstreamCredentials
}

type upstreamCredentials struct {
	HeaderValues    map[string]string
	QueryParameters map[string]string
	BearerToken     string
}

func loadConfig() (serverConfig, error) {
	originAllowlistEnv := strings.TrimSpace(os.Getenv(envKeyOriginAllowlist))
	if originAllowlistEnv == "" {
		return serverConfig{}, fmt.Errorf("missing %s", envKeyOriginAllowlist)
	}
	allowedOrigins := make(map[string]struct{})
	for _, originItem := range strings.Split(originAllowlistEnv, ",") {
		trimmed := strings.TrimSpace(originItem)
		if trimmed != "" {
			allowedOrigins[trimmed] = struct{}{}
		}
	}

	listenAddress := os.Getenv(envKeyListenAddress)
	if listenAddress == "" {
		listenAddress = defaultListenAddress
	}

	tokenLifetimeSeconds := defaultTokenLifetimeSeconds
	if lifetimeEnv := strings.TrimSpace(os.Getenv(envKeyTokenLifetimeSeconds)); lifetimeEnv != "" {
		if parsedLifetime, parseLifetimeError := strconv.Atoi(lifetimeEnv); parseLifetimeError == nil && parsedLifetime > 0 {
			tokenLifetimeSeconds = parsedLifetime
		}
	}

	rateLimitPerMinute := defaultRateLimitPerMinute
	if rateEnv := strings.TrimSpace(os.Getenv(envKeyRateLimitPerMinute)); rateEnv != "" {
		if parsedRate, parseRateError := strconv.Atoi(rateEnv); parseRateError == nil && parsedRate > 0 {
			rateLimitPerMinute = parsedRate
		}
	}

	upstreamTimeoutSeconds := defaultUpstreamTimeoutSeconds
	if timeoutEnv := strings.TrimSpace(os.Getenv(envKeyUpstreamTimeoutSeconds)); timeoutEnv != "" {
		if parsedTimeout, parseTimeoutError := strconv.Atoi(timeoutEnv); parseTimeoutError == nil && parsedTimeout > 0 {
			upstreamTimeoutSeconds = parsedTimeout
		}
	}

	jwtHmacSecret := strings.TrimSpace(os.Getenv(envKeyJwtHmacKey))
	if len(jwtHmacSecret) < 16 {
		return serverConfig{}, fmt.Errorf("weak or missing %s", envKeyJwtHmacKey)
	}

	upstreamRoutes, routesError := buildUpstreamRoutes(
		strings.TrimSpace(os.Getenv(envKeyUpstreamRoutes)),
		strings.TrimSpace(os.Getenv(envKeyUpstreamBaseURL)),
		strings.TrimSpace(os.Getenv(envKeyUpstreamServiceSecret)),
	)
	if routesError != nil {
		return serverConfig{}, routesError
	}

	return serverConfig{
		ListenAddress:      listenAddress,
		AllowedOrigins:     allowedOrigins,
		TokenLifetime:      time.Duration(tokenLifetimeSeconds) * time.Second,
		JwtHmacKey:         []byte(jwtHmacSecret),
		UpstreamRoutes:     upstreamRoutes,
		RateLimitPerMinute: rateLimitPerMinute,
		UpstreamTimeout:    time.Duration(upstreamTimeoutSeconds) * time.Second,
	}, nil
}

func buildUpstreamRoutes(rawRoutes string, legacyBaseURL string, legacyServiceSecret string) ([]upstreamRouteConfig, error) {
	if rawRoutes != "" {
		return parseExplicitRoutes(rawRoutes)
	}
	if legacyBaseURL == "" {
		return nil, fmt.Errorf("missing %s or %s", envKeyUpstreamRoutes, envKeyUpstreamBaseURL)
	}
	parsedBaseURL, parseError := url.Parse(legacyBaseURL)
	if parseError != nil {
		return nil, fmt.Errorf("bad %s: %v", envKeyUpstreamBaseURL, parseError)
	}
	requiredRoute := upstreamRouteConfig{
		PublicPath:      "/api",
		UpstreamBaseURL: parsedBaseURL,
		Credentials: upstreamCredentials{
			HeaderValues:    map[string]string{},
			QueryParameters: map[string]string{},
		},
	}
	if legacyServiceSecret != "" {
		requiredRoute.Credentials.QueryParameters["key"] = legacyServiceSecret
	}
	return []upstreamRouteConfig{requiredRoute}, nil
}

type upstreamRouteDefinition struct {
	PublicPath      string                       `json:"publicPath"`
	UpstreamBaseURL string                       `json:"upstreamBaseUrl"`
	Credentials     upstreamCredentialDefinition `json:"credentials"`
}

type upstreamCredentialDefinition struct {
	HeaderValues    map[string]string `json:"headers"`
	QueryParameters map[string]string `json:"query"`
	BearerToken     string            `json:"bearerToken"`
}

func parseExplicitRoutes(rawRoutes string) ([]upstreamRouteConfig, error) {
	var definitions []upstreamRouteDefinition
	if unmarshalError := json.Unmarshal([]byte(rawRoutes), &definitions); unmarshalError != nil {
		return nil, fmt.Errorf("bad %s json: %w", envKeyUpstreamRoutes, unmarshalError)
	}
	if len(definitions) == 0 {
		return nil, fmt.Errorf("%s must define at least one route", envKeyUpstreamRoutes)
	}
	result := make([]upstreamRouteConfig, 0, len(definitions))
	seenPaths := make(map[string]struct{})
	for index, definition := range definitions {
		cleanedPath, cleanError := normalizePublicPath(definition.PublicPath)
		if cleanError != nil {
			return nil, fmt.Errorf("%s[%d].publicPath: %w", envKeyUpstreamRoutes, index, cleanError)
		}
		if _, exists := seenPaths[cleanedPath]; exists {
			return nil, fmt.Errorf("duplicate publicPath %s in %s", cleanedPath, envKeyUpstreamRoutes)
		}
		if definition.UpstreamBaseURL == "" {
			return nil, fmt.Errorf("%s[%d].upstreamBaseUrl is required", envKeyUpstreamRoutes, index)
		}
		parsedURL, parseError := url.Parse(definition.UpstreamBaseURL)
		if parseError != nil {
			return nil, fmt.Errorf("bad %s[%d].upstreamBaseUrl: %v", envKeyUpstreamRoutes, index, parseError)
		}
		route := upstreamRouteConfig{
			PublicPath:      cleanedPath,
			UpstreamBaseURL: parsedURL,
			Credentials: upstreamCredentials{
				HeaderValues:    sanitizeCredentialMap(definition.Credentials.HeaderValues),
				QueryParameters: sanitizeCredentialMap(definition.Credentials.QueryParameters),
				BearerToken:     strings.TrimSpace(definition.Credentials.BearerToken),
			},
		}
		result = append(result, route)
		seenPaths[cleanedPath] = struct{}{}
	}
	return result, nil
}

func normalizePublicPath(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", fmt.Errorf("publicPath is required")
	}
	if trimmed[0] != '/' {
		return "", fmt.Errorf("publicPath must start with /")
	}
	cleaned := path.Clean(trimmed)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned, nil
}

func sanitizeCredentialMap(input map[string]string) map[string]string {
	if len(input) == 0 {
		return map[string]string{}
	}
	sanitized := make(map[string]string)
	for key, value := range input {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		sanitized[trimmedKey] = value
	}
	return sanitized
}
