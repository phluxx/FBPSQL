package main

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
)

func main() {
	r, err := http.Get(fmt.Sprintf("http://127.0.0.1:%s/health", os.Getenv("HTTP_PORT")))
	if err != nil {
		os.Exit(1)
	}

	defer r.Body.Close() // nolint: errcheck
	buf, _ := io.ReadAll(r.Body)
	if len(buf) > 0 {
		slog.Info("Healthcheck", "response", string(buf))
	}
	if r.StatusCode != 200 {
		os.Exit(1)
	}
}
