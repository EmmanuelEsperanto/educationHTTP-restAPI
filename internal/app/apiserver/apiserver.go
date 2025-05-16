package apiserver

import (
	"database/sql"
	"educationHTTP-restAPI/internal/app/store/sqlstore"
	"github.com/gorilla/sessions"
	"net/http"
)

// Start ...
func Start(config *Config) (s *Server, err error) {
	db, err := newDB(config.DatabaseURL)
	if err != nil {
		return nil, err
	}

	defer db.Close()

	store := sqlstore.New(db)
	sessionStore := sessions.NewCookieStore([]byte(config.SessionKey))
	srv := newServer(store, sessionStore)

	return srv, http.ListenAndServe(config.BindAddr, srv)
}

func newDB(databaseURL string) (*sql.DB, error) {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		return nil, err
	}
	return db, nil
}
