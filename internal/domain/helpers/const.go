package helpers

const (
	authHN = "AuthHelper"
)

const (
	errBcryptPassword        = "failed to bcrypt password"
	errDecryptText           = "failed to decrypt text"
	errEncryptText           = "failed to encrypt text"
	errEmptyEncryptionKey    = "encryption key is empty"
	errEmptyPassword         = "password is empty"
	errMinLenPassword        = "password min length is 8"
	errMaxLenPassword        = "password max length is 32"
	errParseEmailTemplate    = "failed to parse email template"
	errSendEmail             = "failed to send email"
	errShouldContainPassword = "password should contain at least one uppercase letter, one lowercase letter, one number, and one special character"
	errTextEmpty             = "text is empty"
)
