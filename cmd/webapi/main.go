package main

import (
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/app"
	"github.com/anhsbolic/go-secure-auth/pkg/config"
	"github.com/anhsbolic/go-secure-auth/pkg/logging"
	"os"
	"os/signal"
)

func main() {
	// Setup App
	mainApp := app.NewApp()
	mainApp.Setup()
	mainApp.Run()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt)
	<-quit
	mainApp.ShutDown()
	logging.Logger().Info(fmt.Sprintf("Server %s gracefully stopped", config.GetConfig().AppName))
}
