package sqlstore

import (
	"time"
)

type RefreshTokenRepository struct {
	store *Store
}

func (r *RefreshTokenRepository) Save(jti string, userID int, expiresAt time.Time) error {
	_, err := r.store.db.Exec(
		"INSERT INTO refresh_tokens (jti, user_id, expires_at) VALUES ($1, $2, $3)",
		jti, userID, expiresAt,
	)
	return err
}

func (r *RefreshTokenRepository) Delete(jti string) error {
	_, err := r.store.db.Exec(`DELETE FROM refresh_tokens WHERE jti = $1`, jti)
	return err
}

func (r *RefreshTokenRepository) Exists(jti string) (bool, error) {
	var count int
	err := r.store.db.QueryRow(
		`SELECT COUNT(*) FROM refresh_tokens WHERE jti = $1 AND expires_at > now()`,
		jti,
	).Scan(&count)
	return count > 0, err
}

func (r *RefreshTokenRepository) DeleteAllByUserID(userID int) error {
	_, err := r.store.db.Exec("DELETE FROM refresh_tokens WHERE user_id = $1", userID)
	return err
}

func (r *RefreshTokenRepository) CountByUserID(userID int) (int, error) {
	var count int
	err := r.store.db.QueryRow("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = $1", userID).Scan(&count)
	return count, err
}
