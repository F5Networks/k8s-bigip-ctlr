package ctlrerrors

// ContextualError is a type of error which depends on specific context
type ContextualError struct {
	Err error
}

// DefiniteError is context independent
type DefiniteError struct {
	Err error
}

func (e ContextualError) Error() string {
	return e.Err.Error()
}

func (e ContextualError) Unwrap() error {
	return e.Err
}

func (e DefiniteError) Error() string {
	return e.Err.Error()
}

func (e DefiniteError) Unwrap() error {
	return e.Err
}
