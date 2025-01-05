package errorHandler

// PanicIfError is a helper function to panic if error is not nil
func PanicIfError(err error) {
	if err != nil {
		panic(err)
	}
}
