package store

import "time"

type (
	// Store interface ...
	Store interface {
		User() UserRepository
		RefreshToken() RefreshTokenRepository
		CleanUpExpiredRefreshTokens() error
	}
	RefreshTokenRepository interface {
		Save(jti string, userID int, expiresAt time.Time) error
		Delete(jti string) error
		Exists(jti string) (bool, error)
		DeleteAllByUserID(userID int) error
		CountByUserID(userID int) (int, error)
	}
)
