package main

import (
	"net/http"
	"testing"
	"time"
)

func TestNewPanelHTTPServerSetsDefensiveTimeouts(t *testing.T) {
	srv := newPanelHTTPServer("127.0.0.1:9999", http.NewServeMux())
	if srv.ReadHeaderTimeout <= 0 {
		t.Fatalf("ReadHeaderTimeout must be set")
	}
	if srv.ReadTimeout <= 0 {
		t.Fatalf("ReadTimeout must be set")
	}
	if srv.WriteTimeout <= 0 {
		t.Fatalf("WriteTimeout must be set")
	}
	if srv.IdleTimeout <= 0 {
		t.Fatalf("IdleTimeout must be set")
	}
	if srv.ReadHeaderTimeout > 10*time.Second {
		t.Fatalf("ReadHeaderTimeout too large: %s", srv.ReadHeaderTimeout)
	}
}
