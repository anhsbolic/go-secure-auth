package email

type VerificationEmailData struct {
	Name            string
	VerificationURL string
}

type ResetEmailData struct {
	Name     string
	ResetURL string
}

type LoginOTPEmailData struct {
	Name string
	OTP  string
}

type LoginNewMetadata struct {
	Name      string
	UserAgent string
	IPAddress string
}
