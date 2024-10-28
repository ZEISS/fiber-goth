package csrf

import (
	"time"

	"github.com/google/uuid"
	"github.com/valyala/fasthttp"
	goth "github.com/zeiss/fiber-goth"
	"github.com/zeiss/fiber-goth/adapters"
	"github.com/zeiss/pkg/slices"
	"github.com/zeiss/pkg/utilx"

	"github.com/gofiber/fiber/v2"
)

var (
	// ErrMissingHeader is returned when the token is missing from the request.
	ErrMissingHeader = fiber.NewError(fiber.StatusForbidden, "missing csrf token in header")
	// ErrTokenNotFound is returned when the token is not found in the session.
	ErrTokenNotFound = fiber.NewError(fiber.StatusForbidden, "csrf token not found in session")
	// ErrMissingSession is returned when the session is missing from the context.
	ErrMissingSession = fiber.NewError(fiber.StatusForbidden, "missing session in context")
	// ErrGenerateToken is returned when the token generator returns an error.
	ErrGenerateToken = fiber.NewError(fiber.StatusForbidden, "failed to generate csrf token")
)

// HeaderName is the default header name used to extract the token.
const HeaderName = "X-Csrf-Token"

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

const (
	csrfTokenKey contextKey = iota
)

// Config defines the config for csrf middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c *fiber.Ctx) bool

	// Adapter is the adapter used to store the session.
	// Adapter adapters.Adapter
	Adapter adapters.Adapter

	// IgnoredMethods is a list of methods to ignore from CSRF protection.
	// Optional. Default: []string{fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions, fiber.MethodTrace}
	IgnoredMethods []string

	// ErrorHandler is executed when an error is returned from fiber.Handler.
	//
	// Optional. Default: DefaultErrorHandler
	ErrorHandler fiber.ErrorHandler

	// Extractor is the function used to extract the token from the request.
	Extractor func(c *fiber.Ctx) (string, error)

	// Indicates if CSRF cookie is secure.
	// Optional. Default value false.
	CookieSecure bool

	// Decides whether cookie should last for only the browser sesison.
	// Ignores Expiration if set to true
	CookieSessionOnly bool

	// SingleUseToken indicates if the CSRF token be destroyed
	// and a new one generated on each use.
	//
	// Optional. Default: false
	SingleUseToken bool

	// CookieName is the name of the cookie used to store the session.
	CookieName string

	// CookieSameSite is the SameSite attribute of the cookie.
	CookieSameSite fasthttp.CookieSameSite

	// CookiePath is the path of the cookie.
	CookiePath string

	// CookieDomain is the domain of the cookie.
	CookieDomain string

	// CookieHTTPOnly is the HTTPOnly attribute of the cookie.
	CookieHTTPOnly bool

	// TrustedOrigins is a list of origins that are allowed to set the cookie.
	TrustedOrigins []string

	// IdleTimeout is the duration of time before the session expires.
	IdleTimeout time.Duration

	// TokenGenerator is a function that generates a CSRF token.
	TokenGenerator CsrfTokenGenerator
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	IdleTimeout:    30 * time.Minute,
	CookieName:     "csrf_",
	CookieSameSite: fasthttp.CookieSameSiteLaxMode,
	ErrorHandler:   defaultErrorHandler,
	Extractor:      FromHeader(HeaderName),
	TokenGenerator: DefaultCsrfTokenGenerator,
	IgnoredMethods: []string{fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions, fiber.MethodTrace},
}

// CsrfTokenGenerator is a function that generates a CSRF token.
type CsrfTokenGenerator func() (string, error)

// DefaultCsrfTokenGenerator generates a new CSRF token.
func DefaultCsrfTokenGenerator() (string, error) {
	token, err := uuid.NewV7()
	if err != nil {
		return "", err
	}

	return token.String(), nil
}

// default ErrorHandler that process return error from fiber.Handler
func defaultErrorHandler(_ *fiber.Ctx, _ error) error {
	return fiber.ErrForbidden
}

// Helper function to set default values
// nolint:gocyclo
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = ConfigDefault.IdleTimeout
	}

	if cfg.CookieName == "" {
		cfg.CookieName = ConfigDefault.CookieName
	}

	if cfg.CookieSameSite == 0 {
		cfg.CookieSameSite = ConfigDefault.CookieSameSite
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = ConfigDefault.ErrorHandler
	}

	if cfg.Extractor == nil {
		cfg.Extractor = ConfigDefault.Extractor
	}

	if cfg.TokenGenerator == nil {
		cfg.TokenGenerator = ConfigDefault.TokenGenerator
	}

	if cfg.IgnoredMethods == nil {
		cfg.IgnoredMethods = ConfigDefault.IgnoredMethods
	}

	return cfg
}

// New creates a new csrf middleware.
// nolint:gocyclo
func New(config ...Config) fiber.Handler {
	// Set default config
	cfg := configDefault(config...)

	// Return new handler
	return func(c *fiber.Ctx) error {
		// Skip middleware if Next returns true
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		// extract the session
		session, err := goth.SessionFromContext(c)
		if err != nil {
			return cfg.ErrorHandler(c, ErrMissingSession)
		}

		// Skip middleware if the method is ignored
		if slices.Any(func(method string) bool { return method == c.Method() }, cfg.IgnoredMethods...) {
			return c.Next()
		}

		// extract the token
		token, err := cfg.Extractor(c)
		if err != nil {
			return cfg.ErrorHandler(c, ErrTokenNotFound)
		}

		// if the token is empty, abort
		if utilx.Empty(token) {
			return cfg.ErrorHandler(c, ErrTokenNotFound)
		}

		if session.GetCsrfToken().HasExpired() {
			return cfg.ErrorHandler(c, ErrTokenNotFound)
		}

		if !session.GetCsrfToken().IsValid(token) {
			return cfg.ErrorHandler(c, ErrTokenNotFound)
		}

		t, err := cfg.TokenGenerator()
		if err != nil {
			return cfg.ErrorHandler(c, ErrGenerateToken)
		}

		session.CsrfToken = adapters.GothCsrfToken{
			Token:     t,
			ExpiresAt: time.Now().Add(cfg.IdleTimeout),
		}

		session, err = cfg.Adapter.UpdateSession(c.Context(), session)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		// Set the session in the context
		c.Locals(csrfTokenKey, session.CsrfToken)

		// continue stack
		return c.Next()
	}
}

// CsrfTokenFromContext returns the CSRF token from the context.
func CsrfTokenFromContext(c *fiber.Ctx) (string, error) {
	token, ok := c.Locals(csrfTokenKey).(adapters.GothCsrfToken)
	if !ok {
		return "", ErrTokenNotFound
	}

	return token.Token, nil
}

// FromHeader returns a function that extracts token from the request header.
func FromHeader(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Get(param)

		if utilx.Empty(token) {
			return "", ErrMissingHeader
		}

		return token, nil
	}
}
