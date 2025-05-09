package model

import (
	validation "github.com/go-ozzo/ozzo-validation"
	"github.com/go-ozzo/ozzo-validation/is"
	"golang.org/x/crypto/bcrypt"
)

// User ...
type User struct {
	ID                int
	Email             string
	Password          string
	EncryptedPassword string
}

// User Validate...
func (u *User) Validate() error {
	return validation.ValidateStruct(u,
		validation.Field(&u.Email, validation.Required, is.Email),
		validation.Field(&u.Password, validation.By(requiedIf(u.EncryptedPassword == "")), validation.Length(6, 100)),
	)
}

// Before Create ...
func (u *User) BeforeCreate() error {

	if u.Password != "" {
		enc, err := encryptString(u.Password)
		if err != nil {
			return err
		}
		u.EncryptedPassword = enc
	}

	return nil
}

// Encrypt pass ...
func encryptString(s string) (string, error) {

	b, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
	if err != nil {
		return "", err
	}

	return string(b), nil
}
