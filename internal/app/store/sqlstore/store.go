package sqlstore

import (
	"database/sql"
	"educationHTTP-restAPI/internal/app/store"
	_ "github.com/lib/pq"
)

// Store ...
type Store struct {
	db                     *sql.DB
	userRepository         *UserRepository
	refreshTokenRepository *RefreshTokenRepository // <--- добавили
}

func (s *Store) CleanUpExpiredRefreshTokens() error {
	_, err := s.db.Exec(`DELETE FROM refresh_tokens WHERE expires_at < NOW()`)
	return err
}

// New ...
func New(db *sql.DB) *Store {
	return &Store{
		db: db,
	}
}

// User ...
func (s *Store) User() store.UserRepository {
	if s.userRepository != nil {
		return s.userRepository
	}

	s.userRepository = &UserRepository{
		store: s,
	}
	return s.userRepository
}

func (s *Store) RefreshToken() store.RefreshTokenRepository {
	if s.refreshTokenRepository != nil {
		return s.refreshTokenRepository
	}

	s.refreshTokenRepository = &RefreshTokenRepository{
		store: s,
	}
	return s.refreshTokenRepository
}
