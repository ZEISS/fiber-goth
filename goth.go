// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package goth

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
)

var _ GothHandler = (*BeginAuthHandler)(nil)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

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

	sess, err := provider.BeginAuth(stateFromContext(c))
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

// Config caputes the configuration for running the goth middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c *fiber.Ctx) bool

	// BeginAuthHandler ...
	BeginAuthHandler GothHandler

	// Session ...
	Session SessionStore

	// ErrorHandler is executed when an error is returned from fiber.Handler.
	//
	// Optional. Default: DefaultErrorHandler
	ErrorHandler fiber.ErrorHandler
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	ErrorHandler:     defaultErrorHandler,
	BeginAuthHandler: BeginAuthHandler{},
	Session:          NewSessionStore(session.New(defaultSessionConfig)),
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

	return cfg
}

func stateFromContext(ctx *fiber.Ctx) string {
	state := ctx.Query(state)
	if len(state) > 0 {
		return state
	}

	nonce := generateRandomString(64)

	return base64.URLEncoding.EncodeToString(nonce)
}

func generateRandomString(length int) []byte {
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return b
}
