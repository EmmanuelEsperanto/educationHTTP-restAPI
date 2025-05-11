package teststore

import (
	"educationHTTP-restAPI/internal/app/model"
	"educationHTTP-restAPI/internal/app/store"
)

// teststore UserRepository struct ...
type UserRepository struct {
	store *Store
	users map[string]*model.User
}

// teststore-Create test ...
func (r *UserRepository) Create(u *model.User) error {
	if err := u.Validate(); err != nil {
		return err
	}

	if err := u.BeforeCreate(); err != nil {
		return err
	}

	r.users[u.Email] = u
	u.ID = len(r.users)
	return nil
}

// teststore-FindByEmail test ...
func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	u, ok := r.users[email]
	if !ok {
		return nil, store.ErrRecordNotFound
	}
	return u, nil
}
