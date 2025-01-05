package email

type MailHeader struct {
	Subject    string
	Recipients []string
	Cc         []string
	Bcc        []string
}
