package teststore

import (
	"educationHTTP-restAPI/internal/app/model"
	"educationHTTP-restAPI/internal/app/store"
)

// teststore UserRepository struct ...
type UserRepository struct {
	store *Store
	users map[int]*model.User
}

// teststore-Create test ...
func (r *UserRepository) Create(u *model.User) error {
	if err := u.Validate(); err != nil {
		return err
	}

	if err := u.BeforeCreate(); err != nil {
		return err
	}

	u.ID = len(r.users) + 1
	r.users[u.ID] = u
	return nil
}

// teststore-FindByEmail test ...
func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			return u, nil
		}
	}
	return nil, store.ErrRecordNotFound
}

// teststore-Find test ...
func (r *UserRepository) Find(id int) (*model.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, store.ErrRecordNotFound
	}
	return u, nil
}
