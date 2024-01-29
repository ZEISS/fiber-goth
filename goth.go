// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package goth

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
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

var _ goth.Params = (*Params)(nil)

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

// The keys for the values in context
const (
	providerKey contextKey = 0
)

var (
	// ErrMissingProviderName is thrown if the provider cannot be determined.
	ErrMissingProviderName = errors.New("missing provider name in request")
	// ErrMissingSession is thrown if there is no active session.
	ErrMissingSession = errors.New("could not find a matching session for this request")
)

const (
	state    = "state"
	provider = "provider"
)

// SessionStore is the interface to store session information for authentication.
type SessionStore interface {
	// Get ...
	Get(c *fiber.Ctx, key string) (string, error)
	// Update ...
	Update(c *fiber.Ctx, key, value string) error
	// Destroy ...
	Destroy(c *fiber.Ctx) error
	// Interface ...
	Interface() any
}

var _ SessionStore = (*sessionStore)(nil)

// NewSessionStore returns a new default store based on the session middleware.
func NewSessionStore(store *session.Store) *sessionStore {
	return &sessionStore{
		store: store,
	}
}

type sessionStore struct {
	store *session.Store
}

// Get returns session data.
func (s *sessionStore) Get(c *fiber.Ctx, key string) (string, error) {
	session, err := s.store.Get(c)
	if err != nil {
		return "", err
	}

	value := session.Get(key)
	if value == nil {
		return "", ErrMissingSession
	}

	rdata := strings.NewReader(value.(string))
	r, err := gzip.NewReader(rdata)
	if err != nil {
		return "", err
	}

	v, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}

	return string(v), nil
}

// Destroy the session.
func (s *sessionStore) Destroy(c *fiber.Ctx) error {
	session, err := s.store.Get(c)
	if err != nil {
		return err
	}

	err = session.Destroy()
	if err != nil {
		return err
	}

	return nil
}

// Update updates session data.
func (s *sessionStore) Update(c *fiber.Ctx, key, value string) error {
	session, err := s.store.Get(c)
	if err != nil {
		return err
	}

	var b bytes.Buffer

	gz := gzip.NewWriter(&b)
	if _, err := gz.Write([]byte(value)); err != nil {
		return err
	}

	if err := gz.Flush(); err != nil {
		return err
	}

	if err := gz.Close(); err != nil {
		return err
	}

	session.Set(key, b.String())

	err = session.Save()
	if err != nil {
		return err
	}

	return nil
}

// Store returns the raw interface.
func (s *sessionStore) Interface() any {
	return s.store
}

// Return the raw store of the used default session
func DefaultSession() any {
	cfg := configDefault()

	return cfg.Session.Interface()
}

// ProviderFromContext returns the provider from the request context.
func ProviderFromContext(c *fiber.Ctx) string {
	return c.Get(fmt.Sprint(providerKey))
}

// BeginAuthHandler is the default handler to begin the authentication process.
type BeginAuthHandler struct{}

// New creates a new handler to begin authentication.
func (BeginAuthHandler) New(cfg Config) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		url, err := GetAuthURLFromContext(c, cfg.Session)
		if err != nil {
			return cfg.ErrorHandler(c, err)
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
			return ErrMissingProviderName
		}

		provider, err := goth.GetProvider(p)
		if err != nil {
			return err
		}

		v, err := cfg.Session.Get(c, p)
		if err != nil {
			return err
		}

		sess, err := provider.UnmarshalSession(v)
		if err != nil {
			return err
		}

		_, err = provider.FetchUser(sess)
		if err == nil {
			return cfg.ResponseFilter(c)
		}

		_, err = sess.Authorize(provider, &Params{ctx: c})
		if err != nil {
			return err
		}

		err = cfg.Session.Update(c, p, sess.Marshal())
		if err != nil {
			return err
		}

		_, err = provider.FetchUser(sess)
		if err != nil {
			return err
		}

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

		err := cfg.Session.Destroy(c)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		return cfg.ResponseFilter(c)
	}
}

// GetAuthURLFromContext returns the provider specific authentication URL.
func GetAuthURLFromContext(c *fiber.Ctx, session SessionStore) (string, error) {
	p := c.Params(provider)
	if p == "" {
		return "", ErrMissingProviderName
	}

	provider, err := goth.GetProvider(p)
	if err != nil {
		return "", err
	}

	state, err := stateFromContext(c)
	if err != nil {
		return "", err
	}

	sess, err := provider.BeginAuth(state)
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	err = session.Update(c, p, sess.Marshal())
	if err != nil {
		return "", err
	}

	return url, err
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

	// Session stores an authentication session.
	Session SessionStore

	// Response filter that is executed when responses need to returned.
	ResponseFilter func(c *fiber.Ctx) error

	// ErrorHandler is executed when an error is returned from fiber.Handler.
	//
	// Optional. Default: DefaultErrorHandler
	ErrorHandler fiber.ErrorHandler
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	ErrorHandler:        defaultErrorHandler,
	ResponseFilter:      defaultResponseFilter,
	BeginAuthHandler:    BeginAuthHandler{},
	CompleteAuthHandler: CompleteAuthCompleteHandler{},
	LogoutHandler:       LogoutHandler{},
	Session:             NewSessionStore(session.New(defaultSessionConfig)),
}

// default ErrorHandler that process return error from fiber.Handler
func defaultErrorHandler(_ *fiber.Ctx, _ error) error {
	return fiber.ErrBadRequest
}

// default filter for response that process default return.
func defaultResponseFilter(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusOK)
}

var defaultSessionConfig = session.Config{
	KeyLookup:      fmt.Sprintf("cookie:%s", gothic.SessionName),
	CookieHTTPOnly: true,
}

// Helper function to set default values
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
	}

	if cfg.Session == nil {
		cfg.Session = NewSessionStore(session.New(defaultSessionConfig))
	}

	if cfg.ResponseFilter == nil {
		cfg.ResponseFilter = defaultResponseFilter
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
