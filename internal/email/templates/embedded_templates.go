package templates

import "embed"

//go:embed email-verification.html
var EmailVerificationTemplate embed.FS

//go:embed login-new-metadata.html
var LoginNewMetadataTemplate embed.FS

//go:embed login-otp.html
var LoginOtpTemplate embed.FS

//go:embed password-reset.html
var PasswordResetTemplate embed.FS
