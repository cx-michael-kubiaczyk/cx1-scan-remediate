package main

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNewTransportTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	get := func(tr *http.Transport) error {
		resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
		if err == nil {
			resp.Body.Close()
		}
		return err
	}

	// default: the test server's private CA is untrusted
	tr, err := newTransport("", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if get(tr) == nil {
		t.Error("expected verification failure with no CA configured")
	}

	// -insecure skips verification
	tr, err = newTransport("", true, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := get(tr); err != nil {
		t.Errorf("insecure: %v", err)
	}

	// -caCert trusts the server's CA, with verification still on
	dir := t.TempDir()
	caFile := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	tr, err = newTransport("", false, caFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := get(tr); err != nil {
		t.Errorf("caCert: %v", err)
	}
}

func TestNewTransportErrors(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	_ = os.WriteFile(bad, []byte("not a cert"), 0o600)

	if _, err := newTransport("", false, bad); err == nil {
		t.Error("expected error for invalid PEM")
	}
	if _, err := newTransport("", false, filepath.Join(t.TempDir(), "missing.pem")); err == nil {
		t.Error("expected error for missing file")
	}
	if _, err := newTransport("", true, bad); err == nil {
		t.Error("expected error for -insecure with -caCert")
	}
	if _, err := newTransport("proxy.corp:8080", false, ""); err == nil {
		t.Error("expected error for proxy without a scheme")
	}
}

func TestNewTransportResponseHeaderTimeout(t *testing.T) {
	tr, err := newTransport("", false, "")
	if err != nil {
		t.Fatal(err)
	}
	if tr.ResponseHeaderTimeout != responseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout = %v, want %v", tr.ResponseHeaderTimeout, responseHeaderTimeout)
	}

	// a server that accepts the request and never answers must not hang the client
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer srv.Close()
	defer close(release)

	tr.ResponseHeaderTimeout = 100 * time.Millisecond
	start := time.Now()
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected a timeout error")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("timeout took %v", time.Since(start))
	}
}

func TestValueOrEnv(t *testing.T) {
	t.Setenv("CX1SR_TEST_A", " from-env ")
	t.Setenv("CX1SR_TEST_B", "second")
	if got := valueOrEnv("flag", "CX1SR_TEST_A"); got != "flag" {
		t.Errorf("flag must win, got %q", got)
	}
	if got := valueOrEnv("  ", "CX1SR_TEST_A"); got != "from-env" {
		t.Errorf("got %q", got)
	}
	if got := valueOrEnv("", "CX1SR_TEST_MISSING", "CX1SR_TEST_B"); got != "second" {
		t.Errorf("got %q", got)
	}
	if got := valueOrEnv("", "CX1SR_TEST_MISSING"); got != "" {
		t.Errorf("got %q", got)
	}
}

type stubTransport struct{ calls int }

func (s *stubTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	s.calls++
	return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{}`)), Header: http.Header{}, Request: r}, nil
}

// the GitHub client must use the shared transport, so -proxy / -insecure / -caCert apply to it too
func TestNewGithubClientUsesTransport(t *testing.T) {
	stub := &stubTransport{}
	client, err := newGithubClient("token", "", stub)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _ = client.Repositories.Get(context.Background(), "o", "r")
	if stub.calls == 0 {
		t.Error("GitHub request did not go through the supplied transport")
	}
}
