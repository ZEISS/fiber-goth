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

// Params ...
type Params struct {
	ctx *fiber.Ctx
}

// Get ...
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

// ErrMissingProviderName is thrown if the provider cannot be determined.
var ErrMissingProviderName = errors.New("missing provider name in request")

const (
	state    = "state"
	provider = "provider"
)

// SessionStore ...
type SessionStore interface {
	Get(c *fiber.Ctx, key string) (string, error)
	Update(c *fiber.Ctx, key, value string) error
	Destroy(c *fiber.Ctx) error
}

var _ SessionStore = (*sessionStore)(nil)

// NewSessionStore ...
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
		return "", errors.New("could not find a matching session for this request")
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

// Destroy ...
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

// ProviderFromContext returns the provider from the request context.
func ProviderFromContext(c *fiber.Ctx) string {
	return c.Get(fmt.Sprint(providerKey))
}

// BeginAuthHandler ...
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

// GothHandler ...
type GothHandler interface {
	New(cfg Config) fiber.Handler
}

// NewBeginAuthHandler creates a new middleware handler to start authentication.
func NewBeginAuthHandler(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return cfg.BeginAuthHandler.New(cfg)
}

// CompleteAuthComplete ...
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

		user, err := provider.FetchUser(sess)
		if err == nil {
			return c.SendString(user.Email)
		}

		_, err = sess.Authorize(provider, &Params{ctx: c})
		if err != nil {
			return err
		}

		err = cfg.Session.Update(c, p, sess.Marshal())
		if err != nil {
			return err
		}

		user, err = provider.FetchUser(sess)
		if err != nil {
			return err
		}

		return c.SendString(user.Email)
	}
}

// NewBeginCompleteAuthHandler creates a new middleware handler to complete authentication.
func NewCompleteAuthHandler(config ...Config) fiber.Handler {
	cfg := configDefault(config...)

	return cfg.CompleteAuthHandler.New(cfg)
}

// LogoutHandler ...
type LogoutHandler struct{}

// NewLogoutHandler ...
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

		return nil
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

	// BeginAuthHandler ...
	BeginAuthHandler GothHandler

	// CompleteAuthHandler ...
	CompleteAuthHandler GothHandler

	// LogoutHandler ...
	LogoutHandler GothHandler

	// Session ...
	Session SessionStore

	// ErrorHandler is executed when an error is returned from fiber.Handler.
	//
	// Optional. Default: DefaultErrorHandler
	ErrorHandler fiber.ErrorHandler
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	ErrorHandler:        defaultErrorHandler,
	BeginAuthHandler:    BeginAuthHandler{},
	CompleteAuthHandler: CompleteAuthCompleteHandler{},
	LogoutHandler:       LogoutHandler{},
	Session:             NewSessionStore(session.New(defaultSessionConfig)),
}

// default ErrorHandler that process return error from fiber.Handler
func defaultErrorHandler(_ *fiber.Ctx, _ error) error {
	return fiber.ErrBadRequest
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
