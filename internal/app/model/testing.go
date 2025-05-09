package model

import "testing"

// test user ...
func TestUser(t *testing.T) *User {
	return &User{
		Email:    "user@example.org",
		Password: "password",
	}
}
