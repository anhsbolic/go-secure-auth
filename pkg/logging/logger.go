package logging

import (
	"github.com/anhsbolic/go-secure-auth/pkg/config"
	"github.com/sirupsen/logrus"
	"os"
)

func Logger() *logrus.Logger {
	// Get Config
	cfg := config.GetConfig()

	// Set Logger
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})
	logLevel := logrus.TraceLevel
	logOutput := os.Stdout
	if cfg.AppEnv == "production" {
		logLevel = logrus.InfoLevel
		logOutput = os.Stdout
	}
	logger.SetLevel(logLevel)
	logger.SetOutput(logOutput)

	return logger
}
