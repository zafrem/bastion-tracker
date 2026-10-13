package rest

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func corsHeader(t *testing.T, f *testFixture, origin string) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	return w.Header().Get("Access-Control-Allow-Origin")
}

func TestCORS_NoHeadersByDefault(t *testing.T) {
	f := newFixture(t)
	if got := corsHeader(t, f, "https://evil.example"); got != "" {
		t.Errorf("default must send no CORS headers, got %q", got)
	}
}

func TestCORS_OnlyAllowlistedOriginsEchoed(t *testing.T) {
	f := newFixture(t, WithCORSOrigins([]string{"https://ops.example"}))
	if got := corsHeader(t, f, "https://ops.example"); got != "https://ops.example" {
		t.Errorf("allowed origin: got %q", got)
	}
	if got := corsHeader(t, f, "https://evil.example"); got != "" {
		t.Errorf("disallowed origin must get no header, got %q", got)
	}
}

func TestCORS_PreflightForDisallowedOriginIsRejected(t *testing.T) {
	f := newFixture(t, WithCORSOrigins([]string{"https://ops.example"}))
	req := httptest.NewRequest(http.MethodOptions, "/v1/events", nil)
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	f.handler.ServeHTTP(w, req)
	if w.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("preflight leaked CORS header to a disallowed origin")
	}
}

func TestClientIP_ForwardedHeaderOnlyHonouredBehindTrustedProxy(t *testing.T) {
	for _, trust := range []bool{false, true} {
		var got string
		h := clientIPMiddleware(trust)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			got = r.RemoteAddr
		}))
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		h.ServeHTTP(httptest.NewRecorder(), req)
		want := "10.0.0.1:1234"
		if trust {
			want = "6.6.6.6"
		}
		if got != want {
			t.Errorf("trustProxy=%v: remote addr = %q, want %q", trust, got, want)
		}
	}
}
