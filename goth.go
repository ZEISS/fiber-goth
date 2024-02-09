// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package goth

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/valyala/fasthttp"
	"github.com/zeiss/fiber-goth/adapters"
	"github.com/zeiss/fiber-goth/providers"
)

var _ GothHandler = (*BeginAuthHandler)(nil)

const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

// Params maps the parameters of the Fiber context to the gothic context.
type Params struct {
	ctx *fiber.Ctx
}

// Get returns the value of a query paramater.
func (p *Params) Get(key string) string {
	return p.ctx.Query(key)
}

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

// The keys for the values in context
const (
	providerKey contextKey = iota
	tokenKey
)

var (
	// ErrMissingProviderName is thrown if the provider cannot be determined.
	ErrMissingProviderName = errors.New("missing provider name in request")
	// ErrMissingSession is thrown if there is no active session.
	ErrMissingSession = errors.New("could not find a matching session for this request")
	// ErrMissingCookie is thrown if the cookie is missing.
	ErrMissingCookie = errors.New("missing session cookie")
)

const (
	state    = "state"
	provider = "provider"
)

// ProviderFromContext returns the provider from the request context.
func ProviderFromContext(c *fiber.Ctx) string {
	return c.Get(fmt.Sprint(providerKey))
}

// SessionHandler is the default handler for the session.
type SessionHandler struct{}

// New creates a new handler to manage the session.
func (SessionHandler) New(cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		// cookie := c.Cookies(cfg.CookieName)
		// if cookie == "" {
		// 	return cfg.IndexHandler(c)
		// }

		// session, err := cfg.Adapter.GetSession(c.Context(), cookie)
		// if err != nil {
		// 	return cfg.ErrorHandler(c, err)
		// }

		// if !session.IsValid() {
		// 	return cfg.IndexHandler(c)
		// }

		return c.Next()
	}
}

// NewSessionHandler returns a new default session handler.
func NewSessionHandler(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return cfg.SessionHandler.New(cfg)
}

// BeginAuthHandler is the default handler to begin the authentication process.
type BeginAuthHandler struct{}

// New creates a new handler to begin authentication.
func (BeginAuthHandler) New(cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		p := c.Params(provider)
		if p == "" {
			return ErrMissingProviderName
		}

		provider, err := providers.GetProvider(p)
		if err != nil {
			return err
		}

		state, err := stateFromContext(c)
		if err != nil {
			return err
		}

		intent, err := provider.BeginAuth(c.Context(), cfg.Adapter, state)
		if err != nil {
			return err
		}

		url, err := intent.GetAuthURL()
		if err != nil {
			return err
		}

		return c.Redirect(url, fiber.StatusTemporaryRedirect)
	}
}

// GothHandler is the interface for defining handlers for the middleware.
type GothHandler interface {
	New(cfg Config) fiber.Handler
}

// NewBeginAuthHandler creates a new middleware handler to start authentication.
func NewBeginAuthHandler(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return cfg.BeginAuthHandler.New(cfg)
}

// CompleteAuthComplete is the default handler to complete the authentication process.
type CompleteAuthCompleteHandler struct{}

// New creates a new handler to complete authentication.
//
//nolint:gocyclo
func (CompleteAuthCompleteHandler) New(cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		p := c.Params(provider)
		if p == "" {
			return cfg.ErrorHandler(c, ErrMissingProviderName)
		}

		provider, err := providers.GetProvider(p)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		user, err := provider.CompleteAuth(c.Context(), cfg.Adapter, &Params{ctx: c})
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		duration, err := time.ParseDuration(cfg.Expiry)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}
		expires := time.Now().Add(duration)

		session, err := cfg.Adapter.CreateSession(c.Context(), user.ID, expires)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		cookieValue := fasthttp.Cookie{}
		cookieValue.SetKeyBytes([]byte(cfg.CookieName))
		cookieValue.SetValueBytes([]byte(session.SessionToken))
		cookieValue.SetHTTPOnly(true)
		cookieValue.SetSameSite(fasthttp.CookieSameSiteLaxMode)
		cookieValue.SetExpire(expires)
		cookieValue.SetPath("/")

		c.Response().Header.SetCookie(&cookieValue)

		return cfg.ResponseFilter(c)
	}
}

// NewBeginCompleteAuthHandler creates a new middleware handler to complete authentication.
func NewCompleteAuthHandler(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return cfg.CompleteAuthHandler.New(cfg)
}

// LogoutHandler is the default handler for the logout process.
type LogoutHandler struct{}

// NewLogoutHandler returns a new default logout handler.
func NewLogoutHandler(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return cfg.LogoutHandler.New(cfg)
}

// New creates a new handler to logout.
func (LogoutHandler) New(cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		token, err := cfg.Extractor(c)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		err = cfg.Adapter.DeleteSession(c.Context(), token)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		c.ClearCookie(cfg.CookieName)

		return cfg.ResponseFilter(c)
	}
}

// GetStateFromContext return the state that is returned during the callback.
func GetStateFromContext(ctx *fiber.Ctx) string {
	return ctx.Query(state)
}

// ContextWithProvider returns a new request context containing the provider.
func ContextWithProvider(ctx *fiber.Ctx, provider string) *fiber.Ctx {
	ctx.Set(fmt.Sprint(providerKey), provider)

	return ctx
}

// Config caputes the configuration for running the goth middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c *fiber.Ctx) bool

	// BeginAuthHandler is the handler to start authentication.
	BeginAuthHandler GothHandler

	// CompleteAuthHandler is the handler to complete the authentication.
	CompleteAuthHandler GothHandler

	// LogoutHandler is the handler to logout.
	LogoutHandler GothHandler

	// SessionHandler is the handler to manage the session.
	SessionHandler GothHandler

	// IndexHandler is the handler to display the index.
	IndexHandler fiber.Handler

	// Response filter that is executed when responses need to returned.
	ResponseFilter func(c *fiber.Ctx) error

	// Secret is the secret used to sign the session.
	Secret string

	// Expiry is the duration that the session is valid for.
	Expiry string

	// CookieName is the name of the cookie used to store the session.
	CookieName string

	// Encryptor is the function used to encrypt the session.
	Encryptor func(decryptedString, key string) (string, error)

	// Decryptor is the function used to decrypt the session.
	Decryptor func(encryptedString, key string) (string, error)

	// Adapter is the adapter used to store the session.
	// Adapter adapters.Adapter
	Adapter adapters.Adapter

	// ErrorHandler is executed when an error is returned from fiber.Handler.
	//
	// Optional. Default: DefaultErrorHandler
	ErrorHandler fiber.ErrorHandler

	// Extractor is the function used to extract the token from the request.
	Extractor func(c *fiber.Ctx) (string, error)
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	ErrorHandler:        defaultErrorHandler,
	ResponseFilter:      defaultResponseFilter,
	BeginAuthHandler:    BeginAuthHandler{},
	CompleteAuthHandler: CompleteAuthCompleteHandler{},
	LogoutHandler:       LogoutHandler{},
	SessionHandler:      SessionHandler{},
	IndexHandler:        defaultIndexHandler,
	Encryptor:           EncryptCookie,
	Decryptor:           DecryptCookie,
	Expiry:              "7h",
	CookieName:          "fiber_goth.session",
	Extractor:           TokenFromCookie("fiber_goth.session"),
}

// default ErrorHandler that process return error from fiber.Handler
func defaultErrorHandler(_ *fiber.Ctx, _ error) error {
	return fiber.ErrBadRequest
}

// default filter for response that process default return.
func defaultResponseFilter(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusOK)
}

// default index handler that process default return.
func defaultIndexHandler(c *fiber.Ctx) error {
	if c.Path() == "/login" {
		return c.Next()
	}

	return c.Redirect("/login", fiber.StatusTemporaryRedirect)
}

// Helper function to set default values
// nolint:gocyclo
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
	}

	if cfg.ResponseFilter == nil {
		cfg.ResponseFilter = defaultResponseFilter
	}

	if cfg.Extractor == nil {
		cfg.Extractor = ConfigDefault.Extractor
	}

	if cfg.BeginAuthHandler == nil {
		cfg.BeginAuthHandler = ConfigDefault.BeginAuthHandler
	}

	if cfg.CompleteAuthHandler == nil {
		cfg.CompleteAuthHandler = ConfigDefault.CompleteAuthHandler
	}

	if cfg.LogoutHandler == nil {
		cfg.LogoutHandler = ConfigDefault.LogoutHandler
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = ConfigDefault.ErrorHandler
	}

	if cfg.SessionHandler == nil {
		cfg.SessionHandler = ConfigDefault.SessionHandler
	}

	if cfg.IndexHandler == nil {
		cfg.IndexHandler = ConfigDefault.IndexHandler
	}

	if cfg.Encryptor == nil {
		cfg.Encryptor = ConfigDefault.Encryptor
	}

	if cfg.Decryptor == nil {
		cfg.Decryptor = ConfigDefault.Decryptor
	}

	if cfg.Expiry == "" {
		cfg.Expiry = ConfigDefault.Expiry
	}

	if cfg.CookieName == "" {
		cfg.CookieName = ConfigDefault.CookieName
	}

	return cfg
}

func stateFromContext(ctx *fiber.Ctx) (string, error) {
	state := ctx.Query(state)
	if len(state) > 0 {
		return state, nil
	}

	nonce, err := generateRandomString(64)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(nonce), nil
}

func generateRandomString(n int) ([]byte, error) {
	b := make([]byte, n)

	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return b, err
		}
		b[i] = charset[num.Int64()]
	}

	return b, nil
}

// TokenFromContext returns the token from the request context.
func TokenFromContext(c *fiber.Ctx) string {
	token, ok := c.Locals(tokenKey).(string)
	if !ok {
		return ""
	}

	return token
}

// TokenFromCookie returns a function that extracts token from the cookie header.
func TokenFromCookie(param string) func(c *fiber.Ctx) (string, error) {
	return func(c *fiber.Ctx) (string, error) {
		token := c.Cookies(param)
		if token == "" {
			return "", ErrMissingCookie
		}

		return token, nil
	}
}
