package main

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestArgValue(t *testing.T) {
	cases := []struct {
		args []string
		name string
		want string
		ok   bool
	}{
		{[]string{"-caCert", "a.pem"}, "caCert", "a.pem", true},
		{[]string{"--caCert=a.pem"}, "caCert", "a.pem", true},
		{[]string{"-cx1", "x", "-caCert=b.pem"}, "caCert", "b.pem", true},
		{[]string{"-cx1", "-caCert"}, "caCert", "", true},
		{[]string{"-cx1", "caCert"}, "caCert", "", false},
		{[]string{"-proxy"}, "caCert", "", false},
	}
	for _, c := range cases {
		got, ok := argValue(c.args, c.name)
		if got != c.want || ok != c.ok {
			t.Errorf("argValue(%v, %q) = %q,%v want %q,%v", c.args, c.name, got, ok, c.want, c.ok)
		}
	}
}

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
