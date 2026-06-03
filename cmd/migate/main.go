package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

func main() {
	var host string
	var port int
	flag.StringVar(&host, "host", "0.0.0.0", "bind host")
	flag.IntVar(&port, "port", 9999, "bind port")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><title>MiGate</title></head><body><h1>MiGate Go Lite</h1><p>轻量面板-style single-binary panel.</p></body></html>`))
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","mode":"go-lite"}`))
	})

	addr := fmt.Sprintf("%s:%d", host, port)
	log.Printf("MiGate listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
