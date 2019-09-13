package fpast2l

import (
	"errors"
	"strings"
)

const (
	errorPrefix         = "fpast2l: "
	internalErrorPrefix = "(internal) "
)

// Errors.
var (
	ErrBadKeySize        = Error{errors.New("bad key size")}
	ErrBadHeader         = Error{errors.New("bad header")}
	ErrBadEncoding       = Error{errors.New("bad encoding")}
	ErrBadEncryption     = Error{errors.New("decryption failed")}
	ErrEngNotInitialized = Error{errors.New("eng not properly initialized")}
)

// Error is an error returned by this package.
type Error struct{ error }

// Error implements the builtin error interface.
// It returns the string representation of the Error.
func (e Error) Error() string { return errorPrefix + e.error.Error() }

// String implements fmt.Stringer interface.
// It returns the string representation of the error
// that is wrapped by the Error e.
func (e Error) String() string { return e.error.Error() }

// Unwrap facilitates the errors.Unwrap function.
// It returns the error wrapped by Error e.
func (e Error) Unwrap() error { return e.error }

// Internal returns whether Error was a package-internal error.
// Package-internal errors are worst-case
// and typically should not leak outside of this package.
func (e Error) Internal() bool {
	return strings.HasPrefix(e.String(), internalErrorPrefix)
}

// internal constructs an error from s
// and returns it wrapped in an Error.
func internal(s string) error {
	return Error{errors.New(internalErrorPrefix + s)}
}

// AsError wraps err in a Error
// unless err is itself a Error
// then it returns err.
func AsError(err error) Error {
	if e, ok := err.(Error); ok {
		return e
	}

	return Error{err}
}
