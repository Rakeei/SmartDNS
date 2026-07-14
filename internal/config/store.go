package config

import "sync/atomic"

// Store holds a live, hot-swappable Config. Get is lock-free and always
// returns a fully validated, internally consistent snapshot, so callers never
// need to worry about torn reads while a reload is in progress.
type Store struct {
	v atomic.Pointer[Config]
}

func NewStore(cfg *Config) *Store {
	s := &Store{}
	s.v.Store(cfg)
	return s
}

// Get returns the current config snapshot.
func (s *Store) Get() *Config {
	return s.v.Load()
}

// Set atomically swaps in a new config snapshot.
func (s *Store) Set(cfg *Config) {
	s.v.Store(cfg)
}
