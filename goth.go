// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package goth

import (
	"github.com/gofiber/fiber/v2"
	"github.com/markbates/goth"
)

var _ GothHandler = (*BeginAuthHandler)(nil)

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

// The keys for the values in context
const (
	providerKey contextKey = 0
)

// ProviderFromContext returns the provider from the request context.
func ProviderFromContext(c *fiber.Ctx) {
}

// BeginAuthHandler
type BeginAuthHandler struct{}

// New creates a new handler to begin authentication.
func (BeginAuthHandler) New(cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		url, err := GetAuthURLFromContext(c)
		if err != nil {
			return c.Status(fiber.StatusBadRequest).SendString(err.Error())
		}

		return c.Redirect(url, fiber.StatusTemporaryRedirect)
	}
}

// GothHandler ...
type GothHandler interface {
	New(cfg Config) fiber.Handler
}

// NewBeginAuthHandler creates a new middleware handler to start authentication.
func NewBeginAuthHandler(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return cfg.BeginAuthHandler.New(cfg)
}

// GetAuthURLFromContext returns the provider specific authentication URL.
func GetAuthURLFromContext(c *fiber.Ctx) (string, error) {
	provider, err := goth.GetProvider("")
	if err != nil {
		return "", err
	}

	sess, err := provider.BeginAuth("")
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	return url, err
}

// Config caputes the configuration for running the goth middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c *fiber.Ctx) bool

	// BeginAuthHandler ...
	BeginAuthHandler GothHandler
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	BeginAuthHandler: BeginAuthHandler{},
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return configDefault()
	}

	// Override default config
	cfg := config[0]

	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
	}

	if cfg.BeginAuthHandler == nil {
		cfg.BeginAuthHandler = ConfigDefault.BeginAuthHandler
	}

	return cfg
}
