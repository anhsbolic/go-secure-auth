package routes

import (
	"github.com/go-playground/validator/v10"
	"github.com/gofiber/fiber/v2"
	"github.com/jmoiron/sqlx"
)

func InitRoutes(f *fiber.App, db *sqlx.DB, validate *validator.Validate) {
	// Health Check
	f.Get("/health-check", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"success": true,
			"message": "Service is Running Properly",
		})
	})

	// INIT ROUTES
	InitAuthRoutes(f, db, validate)
}
