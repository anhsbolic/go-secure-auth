package helpers

import (
	"errors"
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/domain/entities"
	"github.com/anhsbolic/go-secure-auth/internal/dto"
	"github.com/anhsbolic/go-secure-auth/internal/email"
	mailTemplates "github.com/anhsbolic/go-secure-auth/internal/email/templates"
	"github.com/anhsbolic/go-secure-auth/pkg/config"
	"github.com/anhsbolic/go-secure-auth/pkg/crypt"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
	"math/rand"
	"regexp"
	"text/template"
	"time"
)

type AuthHelper interface {
	EncryptText(text string) ([]byte, error)
	DecryptText(encryptedText []byte) (string, error)
	HashText(text string) (string, error)
	ValidatePassword(password string) error
	BcryptPassword(password string) (string, error)
	ComparePassword(hashedPassword string, password string) bool
	GenerateEmailVerificationToken(userID string) string
	GetEmailVerificationTokenExpirationTime() time.Time
	SendVerificationEmail(mailAddress string, username string, verificationToken string) error
	GeneratePasswordResetToken(userID string) string
	GetPasswordResetTokenExpirationTime() time.Time
	SendPasswordResetEmail(mailAddress string, username string, resetToken string) error
	GetSessionExpirationTime() time.Time
	GenerateUserSessionJWT(userSession entities.UserSession) (dto.UserSessionJWT, error)
	GenerateLoginOTP() string
	SendLoginOTPEmail(mailAddress string, username string, loginOTP string) error
	SendLoginNewMetadataEmail(mailAddress string, username string, userAgent string, ipAddress string) error
	ParseRefreshAccessToken(refreshAccessToken string) (string, error)
}

type authHelper struct{}

func (h *authHelper) EncryptText(text string) ([]byte, error) {
	encryptionKey := config.GetConfig().EncryptionKey
	if encryptionKey == "" {
		return nil, fmt.Errorf("[%s|EncryptText] %s", authHN, errEmptyEncryptionKey)
	}

	encryptedText, err := crypt.EncryptAESGCM(encryptionKey, text)
	if err != nil {
		return nil, fmt.Errorf("[%s|EncryptText] %s", authHN, errEncryptText)
	}

	return encryptedText, nil
}

func (h *authHelper) DecryptText(encryptedText []byte) (string, error) {
	encryptionKey := config.GetConfig().EncryptionKey
	if encryptionKey == "" {
		return "", fmt.Errorf("[%s|DecryptText] %s", authHN, errEmptyEncryptionKey)
	}

	decryptedText, err := crypt.DecryptAESGCM(encryptionKey, encryptedText)
	if err != nil {
		return "", fmt.Errorf("[%s|DecryptText] %s", authHN, errDecryptText)
	}

	return decryptedText, nil
}

func (h *authHelper) HashText(text string) (string, error) {
	if text == "" {
		return "", fmt.Errorf("[%s|HashText] %s", authHN, errTextEmpty)
	}

	return crypt.ComputeSHA256(text), nil
}

func (h *authHelper) ValidatePassword(password string) error {
	// empty password
	if password == "" {
		return errors.New(errEmptyPassword)
	}

	// min char : 8
	if len(password) < 8 {
		return errors.New(errMinLenPassword)
	}

	// max char : 32
	if len(password) > 32 {
		return errors.New(errMaxLenPassword)
	}

	// should contain at least one uppercase letter, one lowercase letter, one number, and one special character
	if !regexp.MustCompile(`[a-z]`).MatchString(password) ||
		!regexp.MustCompile(`[A-Z]`).MatchString(password) ||
		!regexp.MustCompile(`\d`).MatchString(password) ||
		!regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(password) {
		return errors.New(errShouldContainPassword)
	}

	return nil
}

func (h *authHelper) BcryptPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), 10)
	if err != nil {
		return "", fmt.Errorf("[%s|BcryptPassword] %s", authHN, errBcryptPassword)
	}

	return string(hashedPassword), nil
}

func (h *authHelper) ComparePassword(hashedPassword string, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

func (h *authHelper) GenerateEmailVerificationToken(userID string) string {
	plainToken := fmt.Sprintf("email_verification|%s|%s", userID, time.Now().Format(time.RFC3339))
	return crypt.ComputeSHA512(plainToken)
}

func (h *authHelper) GetEmailVerificationTokenExpirationTime() time.Time {
	return time.Now().Add(time.Hour * 6)
}

func (h *authHelper) SendVerificationEmail(mailAddress string, username string, verificationToken string) error {
	// set header
	mailHeader := email.MailHeader{
		Subject:    "Email Verification",
		Recipients: []string{mailAddress},
	}

	// set email data
	studentWebUrl := config.GetConfig().WebURL
	verificationUrl := fmt.Sprintf("%s/auth/verify-email?email=%s&token=%s", studentWebUrl, mailAddress, verificationToken)
	mailData := email.VerificationEmailData{
		Name:            username,
		VerificationURL: verificationUrl,
	}

	// parse email template
	mailTemplate, err := template.ParseFS(mailTemplates.EmailVerificationTemplate, "email-verification.html")
	if err != nil {
		return fmt.Errorf("[%s|SendVerificationEmail] %s: %w", authHN, errParseEmailTemplate, err)
	}

	// send email
	err = email.SendNoReplyEmail(mailHeader, mailTemplate, mailData)
	if err != nil {
		return fmt.Errorf("[%s|SendVerificationEmail] %s: %w", authHN, errSendEmail, err)
	}

	return nil
}

func (h *authHelper) GeneratePasswordResetToken(userID string) string {
	plainToken := fmt.Sprintf("password_reset|%s|%s", userID, time.Now().Format(time.RFC3339))
	return crypt.ComputeSHA512(plainToken)
}

func (h *authHelper) GetPasswordResetTokenExpirationTime() time.Time {
	return time.Now().Add(time.Minute * 30)
}

func (h *authHelper) SendPasswordResetEmail(mailAddress string, username string, resetToken string) error {
	// set header
	mailHeader := email.MailHeader{
		Subject:    "Password Reset",
		Recipients: []string{mailAddress},
	}

	// set email data
	studentWebUrl := config.GetConfig().WebURL
	resetUrl := fmt.Sprintf("%s/auth/reset-password?email=%s&token=%s", studentWebUrl, mailAddress, resetToken)
	mailData := email.ResetEmailData{
		Name:     username,
		ResetURL: resetUrl,
	}

	// parse email template
	mailTemplate, err := template.ParseFS(mailTemplates.PasswordResetTemplate, "password-reset.html")
	if err != nil {
		return fmt.Errorf("[%s|SendPasswordResetEmail] %s: %w", authHN, errParseEmailTemplate, err)
	}

	// send email
	err = email.SendNoReplyEmail(mailHeader, mailTemplate, mailData)
	if err != nil {
		return fmt.Errorf("[%s|SendPasswordResetEmail] %s: %w", authHN, errSendEmail, err)
	}

	return nil
}

func (h *authHelper) GetSessionExpirationTime() time.Time {
	return time.Now().Add(24 * time.Hour)
}

func (h *authHelper) GenerateUserSessionJWT(userSession entities.UserSession) (dto.UserSessionJWT, error) {
	// Get Configs
	cfg := config.GetConfig()
	appName := cfg.AppName
	JWTSecretKey := []byte(cfg.JWTSecretKey)

	// Init Values
	result := dto.UserSessionJWT{}
	now := time.Now()
	accessTokenExpires := now.Add(15 * time.Minute).Unix()
	refreshTokenExpires := now.Add(7 * 24 * time.Hour).Unix()

	// Access Token
	accessTokenClaims := jwt.MapClaims{}
	accessTokenClaims["iss"] = appName
	accessTokenClaims["sub"] = userSession.Alias
	accessTokenClaims["sid"] = userSession.SessionID
	accessTokenClaims["jti"] = userSession.AccessUUID
	accessTokenClaims["iat"] = now.Unix()
	accessTokenClaims["nbf"] = now.Unix()
	accessTokenClaims["exp"] = accessTokenExpires
	accessTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, accessTokenClaims)
	accessToken, err := accessTokenJWT.SignedString(JWTSecretKey)
	if err != nil {
		return result, err
	}

	// Refresh Token
	refreshTokenClaims := jwt.MapClaims{}
	refreshTokenClaims["iss"] = appName
	refreshTokenClaims["sub"] = userSession.Alias
	refreshTokenClaims["sid"] = userSession.SessionID
	refreshTokenClaims["jti"] = userSession.RefreshUUID
	refreshTokenClaims["iat"] = now.Unix()
	refreshTokenClaims["nbf"] = now.Unix()
	refreshTokenClaims["exp"] = refreshTokenExpires
	refreshTokenJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshTokenClaims)
	refreshToken, err := refreshTokenJWT.SignedString(JWTSecretKey)
	if err != nil {
		return result, err
	}

	// Set UserSessionJWT then return
	result.AccessToken = accessToken
	result.RefreshToken = refreshToken
	return result, nil
}

func (h *authHelper) GenerateLoginOTP() string {
	return fmt.Sprintf("%06d", rand.Intn(999999))
}

func (h *authHelper) SendLoginOTPEmail(mailAddress string, username string, loginOTP string) error {
	// set header
	mailHeader := email.MailHeader{
		Subject:    "Login OTP",
		Recipients: []string{mailAddress},
	}

	// set email data
	mailData := email.LoginOTPEmailData{
		Name: username,
		OTP:  loginOTP,
	}

	// parse email template
	mailTemplate, err := template.ParseFS(mailTemplates.LoginOtpTemplate, "login-otp.html")
	if err != nil {
		return fmt.Errorf("[%s|SendLoginOTPEmail] %s: %w", authHN, errParseEmailTemplate, err)
	}

	// send email
	err = email.SendNoReplyEmail(mailHeader, mailTemplate, mailData)
	if err != nil {
		return fmt.Errorf("[%s|SendLoginOTPEmail] %s: %w", authHN, errSendEmail, err)
	}

	return nil
}

func (h *authHelper) SendLoginNewMetadataEmail(mailAddress string, username string, userAgent string, ipAddress string) error {
	// set header
	mailHeader := email.MailHeader{
		Subject:    "Login From New Device or Location",
		Recipients: []string{mailAddress},
	}

	// set email data
	mailData := email.LoginNewMetadata{
		Name:      username,
		UserAgent: userAgent,
		IPAddress: ipAddress,
	}

	// parse email template
	mailTemplate, err := template.ParseFS(mailTemplates.LoginNewMetadataTemplate, "login-new-metadata.html")
	if err != nil {
		return fmt.Errorf("[%s|SendLoginNewMetadataEmail] %s: %w", authHN, errParseEmailTemplate, err)
	}

	// send email
	err = email.SendNoReplyEmail(mailHeader, mailTemplate, mailData)
	if err != nil {
		return fmt.Errorf("[%s|SendLoginNewMetadataEmail] %s: %w", authHN, errSendEmail, err)
	}

	return nil
}

func (h *authHelper) ParseRefreshAccessToken(refreshAccessToken string) (string, error) {
	// Get Configs
	cfg := config.GetConfig()
	JWTSecretKey := []byte(cfg.JWTSecretKey)

	// Parse Token
	token, err := jwt.Parse(refreshAccessToken, func(token *jwt.Token) (interface{}, error) {
		return JWTSecretKey, nil
	})
	if err != nil {
		return "", err
	}

	// Validate Token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token")
	}

	// Return refresh UUID
	return claims["jti"].(string), nil
}

func NewAuthHelper() AuthHelper {
	return &authHelper{}
}
