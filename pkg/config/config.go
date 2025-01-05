package config

import (
	"fmt"
	"github.com/joho/godotenv"
	"log"
	"os"
	"strconv"
)

// Environment variables
const (
	AppEnv             = "APP_ENV"
	AppName            = "APP_NAME"
	AppPort            = "APP_PORT"
	AppVersion         = "APP_VERSION"
	LogLevel           = "LOG_LEVEL"
	ShutdownDelay      = "SHUTDOWN_DELAY"
	DbHost             = "DB_HOST"
	DbPort             = "DB_PORT"
	DbUser             = "DB_USER"
	DbName             = "DB_NAME"
	DbPassword         = "DB_PASSWORD"
	DbMaxPool          = "DB_MAX_POOL"
	DbMinPool          = "DB_MIN_POOL"
	DbSslMode          = "DB_SSL_MODE"
	WhitelistedIpList  = "WHITELISTED_IP_LIST"
	EncryptionKey      = "ENCRYPTION_KEY"
	MailSmtpHost       = "MAIL_SMTP_HOST"
	MailSmtpPort       = "MAIL_SMTP_PORT"
	MailUsername       = "MAIL_USERNAME"
	MailPassword       = "MAIL_PASSWORD"
	MailNoReplyAddress = "MAIL_NO_REPLY_ADDRESS"
	MailReplyTo        = "MAIL_REPLY_TO_ADDRESS"
	MailSenderAddress  = "MAIL_SENDER_ADDRESS"
	MailSenderName     = "MAIL_SENDER_NAME"
	WebURL             = "WEB_URL"
	JWTSecretKey       = "JWT_SECRET_KEY"
)

type EnvConfig struct {
	AppEnv             string
	AppName            string
	AppPort            string
	AppVersion         string
	LogLevel           string
	ShutdownDelay      int
	DbDetails          string
	DbName             string
	DbMaxPool          int
	DbMinPool          int
	WhitelistedIpList  string
	EncryptionKey      string
	MailSmtpHost       string
	MailSmtpPort       int
	MailUsername       string
	MailPassword       string
	MailNoReplyAddress string
	MailReplyTo        string
	MailSenderAddress  string
	MailSenderName     string
	WebURL             string
	JWTSecretKey       string
}

// Load environment variables with godotenv and initialize configuration
func init() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}
}

func GetConfig() *EnvConfig {
	dbDetails, dbName := getDbDetails()
	shutdownDelay := getEnvAsInt(ShutdownDelay, 0)

	return &EnvConfig{
		AppEnv:             os.Getenv(AppEnv),
		AppName:            os.Getenv(AppName),
		AppPort:            os.Getenv(AppPort),
		AppVersion:         os.Getenv(AppVersion),
		LogLevel:           os.Getenv(LogLevel),
		ShutdownDelay:      shutdownDelay,
		DbDetails:          dbDetails,
		DbName:             dbName,
		DbMaxPool:          getEnvAsInt(DbMaxPool, 10),
		DbMinPool:          getEnvAsInt(DbMinPool, 5),
		WhitelistedIpList:  os.Getenv(WhitelistedIpList),
		EncryptionKey:      os.Getenv(EncryptionKey),
		MailSmtpHost:       os.Getenv(MailSmtpHost),
		MailSmtpPort:       getEnvAsInt(MailSmtpPort, 587),
		MailUsername:       os.Getenv(MailUsername),
		MailPassword:       os.Getenv(MailPassword),
		MailNoReplyAddress: os.Getenv(MailNoReplyAddress),
		MailReplyTo:        os.Getenv(MailReplyTo),
		MailSenderAddress:  os.Getenv(MailSenderAddress),
		MailSenderName:     os.Getenv(MailSenderName),
		WebURL:             os.Getenv(WebURL),
		JWTSecretKey:       os.Getenv(JWTSecretKey),
	}
}

func getDbDetails() (string, string) {
	host := os.Getenv(DbHost)
	port := os.Getenv(DbPort)
	user := os.Getenv(DbUser)
	password := os.Getenv(DbPassword)
	name := os.Getenv(DbName)
	sslMode := os.Getenv(DbSslMode)

	return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=Asia/Jakarta",
		host, user, password, name, port, sslMode), name
}

// Parse environment variable as int, with default value
func getEnvAsInt(key string, defaultVal int) int {
	if value, exists := os.LookupEnv(key); exists {
		val, err := strconv.Atoi(value)
		if err == nil {
			return val
		}
		log.Println("Invalid integer value for environment variable", key)
	}
	return defaultVal
}

// Parse environment variable as bool, with default value
func getEnvAsBool(key string, defaultVal bool) bool {
	if value, exists := os.LookupEnv(key); exists {
		val, err := strconv.ParseBool(value)
		if err == nil {
			return val
		}
		log.Println("Invalid boolean value for environment variable", key)
	}
	return defaultVal
}
