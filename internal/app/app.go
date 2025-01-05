package app

import (
	"fmt"
	"github.com/anhsbolic/go-secure-auth/internal/app/routes"
	"github.com/anhsbolic/go-secure-auth/internal/infrastructure/api/middleware"
	"github.com/anhsbolic/go-secure-auth/internal/infrastructure/databases/postgres"
	"github.com/anhsbolic/go-secure-auth/pkg/config"
	"github.com/anhsbolic/go-secure-auth/pkg/errorHandler"
	"github.com/anhsbolic/go-secure-auth/pkg/logging"
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/jmoiron/sqlx"
	"time"
)

type App struct {
	f *fiber.App
}

func NewApp() *App {
	return &App{
		f: fiber.New(fiber.Config{
			IdleTimeout:  time.Second * 30,
			ReadTimeout:  time.Second * 30,
			WriteTimeout: time.Second * 30,
			Prefork:      true,
			ErrorHandler: errorHandler.GetHttpErrorHandler,
		}),
	}
}

func (a *App) Setup() {
	// Setup DB Connection : Postgres
	pgCon := postgres.InitConnection()
	pgDb, err := pgCon.GetDB()
	if err != nil {
		logging.Logger().Error(fmt.Sprintf("Failed to connect to database: %v", err))
	}

	// Setup Rate Limiter
	a.f.Use(limiter.New(limiter.Config{
		Max:        300,
		Expiration: 30 * time.Second,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP()
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"message": "Too many requests. Please try again later.",
			})
		},
	}))

	// Setup Global Middlewares
	a.f.Use(middleware.WhitelistIPMiddleware)
	a.f.Use(middleware.LimitRequestSizeMiddleware)
	a.f.Use(middleware.ContentSecurityMiddleware)
	a.f.Use(middleware.BlockSqlInjectionMiddleware)

	// Setup CORS : IF NEEDED --> WHEN BROWSER CAN DIRECT ACCESS THE API

	// Setup Validator
	validate := validator.New()

	// Setup HTTP
	a.setHttp(pgDb, validate)
}

func (a *App) Run() {
	// Start Server
	cfg := config.GetConfig()
	addr := fmt.Sprintf(":%s", cfg.AppPort)
	if err := a.f.Listen(addr); err != nil {
		logging.Logger().Info(fmt.Sprintf("Could not start server: %v\n", err))
	}
}

func (a *App) ShutDown() {
	// Shutdown Server
	if err := a.f.Shutdown(); err != nil {
		logging.Logger().Info(fmt.Sprintf("Could not gracefully shutdown the server: %v\n", err))
	}
}

func (a *App) setHttp(pgDb *sqlx.DB, validate *validator.Validate) {
	// Setup Routes
	routes.InitRoutes(a.f, pgDb, validate)
}
