package email

import (
	"bytes"
	"fmt"
	"github.com/anhsbolic/go-secure-auth/pkg/config"
	"gopkg.in/gomail.v2"
	"text/template"
)

func unsplitComma(values []string) string {
	var to string
	for i, value := range values {
		if i == 0 {
			to = value
		} else {
			to = fmt.Sprintf("%s, %s", to, value)
		}
	}
	return to
}

// SendNoReplyEmail sends an email
func SendNoReplyEmail(header MailHeader, tmpl *template.Template, data interface{}) error {
	// Get Config
	cfg := config.GetConfig()

	// Validate required config
	if cfg.MailNoReplyAddress == "" || cfg.MailSmtpHost == "" || cfg.MailUsername == "" || cfg.MailPassword == "" {
		return fmt.Errorf("missing email configuration values")
	}

	// Init mail
	m := gomail.NewMessage()
	m.SetHeader("From", fmt.Sprintf("%s <%s>", cfg.MailSenderName, cfg.MailNoReplyAddress))
	m.SetHeader("Reply-To", cfg.MailReplyTo)
	m.SetHeader("Subject", header.Subject)
	m.SetHeader("To", unsplitComma(header.Recipients))
	if len(header.Cc) > 0 {
		m.SetHeader("Cc", unsplitComma(header.Cc))
	}
	if len(header.Bcc) > 0 {
		m.SetHeader("Bcc", unsplitComma(header.Bcc))
	}

	// Generate email body
	var body bytes.Buffer
	if err := tmpl.Execute(&body, data); err != nil {
		return fmt.Errorf("error executing template: %w", err)
	}
	m.SetBody("text/html", body.String())

	// Add a plain-text version for better email compatibility
	var plainTextBody bytes.Buffer
	if err := tmpl.ExecuteTemplate(&plainTextBody, "plaintext", data); err == nil {
		m.AddAlternative("text/plain", plainTextBody.String())
	}

	// Send email
	dialer := gomail.NewDialer(cfg.MailSmtpHost, cfg.MailSmtpPort, cfg.MailUsername, cfg.MailPassword)
	err := dialer.DialAndSend(m)
	if err != nil {
		return fmt.Errorf("error sending email: %w", err)
	}

	return nil
}
