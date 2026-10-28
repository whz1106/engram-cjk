package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHostGuard_RejectsForeignHost covers DNS rebinding: the token may be valid
// or missing, but a Host that is not the pinned listener address must be 403 so
// it is distinguishable from a credential failure (401).
func TestHostGuard_RejectsForeignHost(t *testing.T) {
	t.Setenv("ENGRAM_HTTP_TOKEN", "")
	st := newServerTestStore(t)
	srv := New(st, 0)
	srv.SetExpectedHost("127.0.0.1:7777")
	h := srv.Handler()

	for _, tc := range []struct {
		name  string
		token string
	}{
		{name: "without token", token: ""},
		{name: "with token", token: "super-secret-token"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.token != "" {
				t.Setenv("ENGRAM_HTTP_TOKEN", tc.token)
			} else {
				t.Setenv("ENGRAM_HTTP_TOKEN", "")
			}
			req := httptest.NewRequest(http.MethodPost, "/observations", nil)
			req.Host = "attacker.example"
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for untrusted host, got %d body=%q", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestHostGuard_AcceptsPinnedHost verifies the pinned host passes the guard and
// reaches the router (a malformed body may still be 400 — only 401/403 are
// failures here).
func TestHostGuard_AcceptsPinnedHost(t *testing.T) {
	t.Setenv("ENGRAM_HTTP_TOKEN", "super-secret-token")
	st := newServerTestStore(t)
	srv := New(st, 0)
	srv.SetExpectedHost("127.0.0.1:7777")
	h := srv.Handler()

	req := httptest.NewRequest(http.MethodPost, "/observations", nil)
	req.Host = "127.0.0.1:7777"
	req.Header.Set("Authorization", "Bearer super-secret-token")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusUnauthorized || rec.Code == http.StatusForbidden {
		t.Fatalf("expected pinned host to pass the guard, got %d body=%q", rec.Code, rec.Body.String())
	}
}

// TestHostGuard_UnpinnedSkipsHostCheck documents the embedder contract: Handler()
// used directly does not pin a host unless SetExpectedHost is called.
func TestHostGuard_UnpinnedSkipsHostCheck(t *testing.T) {
	t.Setenv("ENGRAM_HTTP_TOKEN", "")
	st := newServerTestStore(t)
	h := New(st, 0).Handler()

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "attacker.example"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusForbidden {
		t.Fatalf("expected no host pinning without SetExpectedHost, got 403")
	}
}

// TestStartPinsListenerHost verifies the production path pins the address the
// listener actually bound (not the requested port), so port 0 also works.
func TestStartPinsListenerHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := New(nil, 0)
	srv.listen = func(_, _ string) (net.Listener, error) { return ln, nil }
	var captured http.Handler
	srv.serve = func(_ net.Listener, h http.Handler) error {
		captured = h
		return nil
	}

	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got, want := srv.pinnedHost(), ln.Addr().String(); got != want {
		t.Fatalf("pinned host = %q, want %q", got, want)
	}
	if captured == nil {
		t.Fatalf("expected the guarded handler to be served")
	}

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "attacker.example"
	rec := httptest.NewRecorder()
	captured.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 from the served handler for a foreign host, got %d", rec.Code)
	}
}

// TestStartPinnedHostWithoutTokenRequiresAuth locks the production combination:
// Start() pins the listener host AND the token is enforced, so a request that
// matches the host still needs the bearer token.
func TestStartPinnedHostWithoutTokenRequiresAuth(t *testing.T) {
	t.Setenv("ENGRAM_HTTP_TOKEN", "super-secret-token")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	srv := New(nil, 0)
	srv.listen = func(_, _ string) (net.Listener, error) { return ln, nil }
	var captured http.Handler
	srv.serve = func(_ net.Listener, h http.Handler) error {
		captured = h
		return nil
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	host := ln.Addr().String()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = host
	captured.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without token on the pinned host, got %d", rec.Code)
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = host
	req.Header.Set("Authorization", "Bearer super-secret-token")
	captured.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 with token on the pinned host, got %d body=%q", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/health", nil)
	req.Host = "attacker.example"
	req.Header.Set("Authorization", "Bearer super-secret-token")
	captured.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for a foreign host with a valid token, got %d", rec.Code)
	}
}
