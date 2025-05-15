package store

import "educationHTTP-restAPI/internal/app/model"

// User repo interface ...
type UserRepository interface {
	Create(*model.User) error
	Find(int) (*model.User, error)
	FindByEmail(string) (*model.User, error)
}
