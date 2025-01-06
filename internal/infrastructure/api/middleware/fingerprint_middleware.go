package middleware

import (
	"github.com/gofiber/fiber/v2"
)

func FingerprintMiddleware(ctx *fiber.Ctx) error {
	userAgent := ctx.Get(fiber.HeaderUserAgent, "Unknown")
	ipAddress := ctx.IP()

	ctx.Locals("userAgent", userAgent)
	ctx.Locals("ipAddress", ipAddress)

	return ctx.Next()
}
