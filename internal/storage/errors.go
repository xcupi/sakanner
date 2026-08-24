package storage

import "errors"

// ErrNotFound is returned by Get methods when no record matches the
// given id.
var ErrNotFound = errors.New("storage: not found")
