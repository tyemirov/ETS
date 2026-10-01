package main

import "testing"

func TestBuildUpstreamRoutesParsesExplicitRoutes(t *testing.T) {
	rawConfig := `[
	  {
	    "publicPath": "/api",
	    "upstreamBaseUrl": "https://primary.example",
	    "credentials": {
	      "headers": {"X-Upstream": "primary"},
	      "query": {"mode": "fast"},
	      "bearerToken": "token-one"
	    }
	  },
	  {
	    "publicPath": "/tiles/",
	    "upstreamBaseUrl": "https://tiles.example",
	    "credentials": {
	      "headers": {"X-Upstream": "tiles"}
	    }
	  }
	]`
	routes, err := buildUpstreamRoutes(rawConfig, "", "")
	if err != nil {
		t.Fatalf("buildUpstreamRoutes: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected two routes, got %d", len(routes))
	}
	if routes[0].PublicPath != "/api" {
		t.Fatalf("expected normalized /api, got %s", routes[0].PublicPath)
	}
	if routes[0].UpstreamBaseURL.String() != "https://primary.example" {
		t.Fatalf("unexpected primary URL: %s", routes[0].UpstreamBaseURL.String())
	}
	if routes[0].Credentials.HeaderValues["X-Upstream"] != "primary" {
		t.Fatalf("expected header to propagate")
	}
	if routes[0].Credentials.QueryParameters["mode"] != "fast" {
		t.Fatalf("expected query parameter to propagate")
	}
	if routes[0].Credentials.BearerToken != "token-one" {
		t.Fatalf("expected bearer token to propagate")
	}
	if routes[1].PublicPath != "/tiles" {
		t.Fatalf("expected trailing slash to be trimmed, got %s", routes[1].PublicPath)
	}
	if routes[1].UpstreamBaseURL.String() != "https://tiles.example" {
		t.Fatalf("unexpected tiles URL: %s", routes[1].UpstreamBaseURL.String())
	}
}

func TestBuildUpstreamRoutesFallsBackToLegacyEnv(t *testing.T) {
	routes, err := buildUpstreamRoutes("", "https://legacy.example", "super-secret")
	if err != nil {
		t.Fatalf("buildUpstreamRoutes fallback: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected single legacy route, got %d", len(routes))
	}
	if routes[0].PublicPath != "/api" {
		t.Fatalf("legacy route should default to /api, got %s", routes[0].PublicPath)
	}
	if routes[0].UpstreamBaseURL.String() != "https://legacy.example" {
		t.Fatalf("unexpected legacy URL: %s", routes[0].UpstreamBaseURL.String())
	}
	if routes[0].Credentials.QueryParameters["key"] != "super-secret" {
		t.Fatalf("legacy secret should populate query parameter")
	}
}

func TestBuildUpstreamRoutesRejectsInvalidPaths(t *testing.T) {
	_, err := buildUpstreamRoutes(`[{"publicPath":"api","upstreamBaseUrl":"https://example"}]`, "", "")
	if err == nil {
		t.Fatalf("expected error for missing leading slash")
	}
}
