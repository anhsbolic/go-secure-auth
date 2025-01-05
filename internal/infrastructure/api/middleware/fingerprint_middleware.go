package middleware

import (
	"context"
	"github.com/gofiber/fiber/v2"
)

func FingerprintMiddleware(ctx *fiber.Ctx) error {
	userContext := ctx.UserContext()

	userAgent := ctx.Get(fiber.HeaderUserAgent, "Unknown")
	userContext = context.WithValue(userContext, "user-agent", userAgent)

	ipAddress := ctx.IP()
	userContext = context.WithValue(userContext, "ip-address", ipAddress)

	ctx.SetUserContext(userContext)

	return ctx.Next()
}
