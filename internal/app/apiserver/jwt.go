package apiserver

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"strconv"
	"time"
)

var (
	accessSecret  = []byte("access_secret")  // храни в env
	refreshSecret = []byte("refresh_secret") // храни в env
)

type tokenClaims struct {
	UserID int `json:"user_id"`
	jwt.RegisteredClaims
}

func generateAccessToken(userID int) (string, error) {
	claims := tokenClaims{
		UserID: userID,
		RegisteredClaims: jwt.RegisteredClaims{
			//ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(30 * time.Second)),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(accessSecret)
}

func generateRefreshToken(userID int) (tokenString string, jti string, expiresAt time.Time, err error) {
	jti = uuid.NewString()
	//expiresAt = time.Now().Add(7 * 24 * time.Hour) // например, 7 дней
	expiresAt = time.Now().Add(2 * time.Minute)
	claims := jwt.RegisteredClaims{
		Subject:   strconv.Itoa(userID),
		ExpiresAt: jwt.NewNumericDate(expiresAt),
		ID:        jti,
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err = token.SignedString(refreshSecret)
	return
}
