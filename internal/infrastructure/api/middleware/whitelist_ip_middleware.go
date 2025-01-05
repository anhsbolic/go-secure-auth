package middleware

import (
	"github.com/anhsbolic/go-secure-auth/pkg/config"
	"github.com/gofiber/fiber/v2"
	"strings"
)

func WhitelistIPMiddleware(ctx *fiber.Ctx) error {
	cfg := config.GetConfig()

	if cfg.AppEnv != "production" {
		return ctx.Next()
	}

	whitelistIpList := cfg.WhitelistedIpList
	allowedIpList := strings.Split(whitelistIpList, ",")

	clientIP := ctx.IP()
	for _, ip := range allowedIpList {
		if clientIP == ip {

			return ctx.Next()
		}
	}

	return ctx.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error": "Access denied",
	})
}
