package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"

	"github.com/phluxx/FBPSQL/internal/config"
	"github.com/phluxx/FBPSQL/internal/handler/v1handler"
	"github.com/phluxx/FBPSQL/internal/store"

	"github.com/rs/cors"
)

func main() {
	var (
		cfg *config.Config
		err error
	)
	cfg, err = config.New()
	if err != nil {
		slog.Error("Failed to load config",
			"error", err,
		)
	}
	mysqlStore, err := store.NewMySQL(cfg)
	if err != nil {
		slog.Error("Failed to connect to database",
			"error", err,
		)
	}
	defer mysqlStore.Close()

	r := v1handler.New(cfg, mysqlStore)
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{fmt.Sprintf("%s://%s", cfg.Http.Proto, cfg.Http.Host)},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Content-Type", "Content-Length", "Accept-Encoding", "X-CSRF-Token", "Authorization"},
		AllowCredentials: true,
	})

	handler := c.Handler(r)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", cfg.Http.Port), handler))
}
