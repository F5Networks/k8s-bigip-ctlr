package ctlrerrors

import (
	"errors"
	"testing"
)

func TestContextualError_Error(t *testing.T) {
	baseErr := errors.New("contextual error occurred")
	ctxErr := ContextualError{Err: baseErr}

	if ctxErr.Error() != baseErr.Error() {
		t.Errorf("expected %q, got %q", baseErr.Error(), ctxErr.Error())
	}
}

func TestContextualError_Unwrap(t *testing.T) {
	baseErr := errors.New("contextual error occurred")
	ctxErr := ContextualError{Err: baseErr}

	if ctxErr.Unwrap() != baseErr {
		t.Errorf("expected %v, got %v", baseErr, ctxErr.Unwrap())
	}
}

func TestDefiniteError_Error(t *testing.T) {
	baseErr := errors.New("definite error occurred")
	defErr := DefiniteError{Err: baseErr}

	if defErr.Error() != baseErr.Error() {
		t.Errorf("expected %q, got %q", baseErr.Error(), defErr.Error())
	}
}

func TestDefiniteError_Unwrap(t *testing.T) {
	baseErr := errors.New("definite error occurred")
	defErr := DefiniteError{Err: baseErr}

	if defErr.Unwrap() != baseErr {
		t.Errorf("expected %v, got %v", baseErr, defErr.Unawrap())
	}
}
