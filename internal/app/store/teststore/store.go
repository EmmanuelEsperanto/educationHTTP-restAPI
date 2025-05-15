package teststore

import (
	"educationHTTP-restAPI/internal/app/model"
	"educationHTTP-restAPI/internal/app/store"
)

// teststore-Store ...
type Store struct {
	userRepository *UserRepository
}

// teststore-New ...
func New() *Store {
	return &Store{}
}

// teststore-User ...
func (s *Store) User() store.UserRepository {
	if s.userRepository != nil {
		return s.userRepository
	}

	s.userRepository = &UserRepository{
		store: s,
		users: make(map[int]*model.User),
	}
	return s.userRepository
}
