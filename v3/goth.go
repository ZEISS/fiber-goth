// 🚀 Fiber is an Express inspired web framework written in Go with 💖
// 📌 API Documentation: https://fiber.wiki
// 📝 Github Repository: https://github.com/gofiber/fiber

package goth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/zeiss/fiber-goth/v3/adapters"
	"github.com/zeiss/fiber-goth/v3/providers"
	"github.com/zeiss/pkg/utilx"
)

var _ Handler = (*BeginAuthHandler)(nil)

const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"

// Environment represents the environment the application is running in.
type Environment string

// StateCtx holds the state of the authentication process.
type StateCtx struct {
	Nounce      string `json:"nounce"`
	RedirectURL string `json:"redirect_url"`
}

const (
	// Noop is a no-op function.
	Noop Environment = "noop"
	// Development environment.
	Development Environment = "development"
	// Testing environment.
	Testing Environment = "testing"
	// Staging environment.
	Staging Environment = "staging"
	// Production environment.
	Production Environment = "production"
)

// Params maps the parameters of the Fiber context to the gothic context.
type Params struct {
	ctx          fiber.Ctx
	codeVerifier string
}

// Get returns the value of a query paramater.
func (p *Params) Get(key string) string {
	return p.ctx.Query(key)
}

// CodeVerifier returns the code verifier for PKCE, if applicable.
func (p *Params) CodeVerifier() string {
	return p.codeVerifier
}

// The contextKey type is unexported to prevent collisions with context keys defined in
// other packages.
type contextKey int

// The keys for the values in context.
const (
	providerKey contextKey = iota
	sessionKey
	tokenKey
	userIDKey
)

const (
	SessionScope      = "session"
	CodeVerifierScope = "code_verifier"
)

// Error is the default error type for the goth middleware.
type Error struct {
	Code    int
	Message string
}

// Error makes it compatible with the `error` interface.
func (e *Error) Error() string {
	return e.Message
}

// NewError creates a new Error instance with an optional message.
func NewError(code int, message ...string) *Error {
	err := &Error{
		Code:    code,
		Message: utils.StatusMessage(code),
	}

	if len(message) > 0 {
		err.Message = message[0]
	}

	return err
}

var (
	// ErrMissingProviderName is thrown if the provider cannot be determined.
	ErrMissingProviderName = NewError(http.StatusBadRequest, "missing provider name in request")
	// ErrMissingSession is thrown if there is no active session.
	ErrMissingSession = NewError(http.StatusBadRequest, "could not find a matching session for this request")
	// ErrBadSession is thrown if the session is invalid.
	ErrBadSession = NewError(http.StatusBadRequest, "session is invalid")
	// ErrMissingUser is thrown if the user is missing.
	ErrMissingUser = NewError(http.StatusBadRequest, "missing user")
	// ErrMissingCookie is thrown if the cookie is missing.
	ErrMissingCookie = NewError(http.StatusBadRequest, "missing session cookie")
	// ErrBadRequest is thrown if the request is invalid.
	ErrBadRequest = NewError(http.StatusBadRequest, "bad request")
)

const (
	state    = "state"
	provider = "provider"
)

// ProviderFromContext returns the provider from the request context.
func ProviderFromContext(c fiber.Ctx) string {
	return c.Get(fmt.Sprint(providerKey))
}

// SessionHandler is the default handler for the session.
type SessionHandler struct{}

// New creates a new handler to manage the session.
func (SessionHandler) New(cfg Config) fiber.Handler {
	return func(c fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		cookie := c.Cookies(cfg.CookieName(SessionScope))
		if cookie == "" {
			return cfg.ErrorHandler(c, ErrMissingCookie)
		}

		session, err := cfg.Adapter.GetSession(c, cookie)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		if !session.IsValid() {
			err := cfg.ErrorHandler(c, err)
			if err != nil {
				return err
			}
		}

		duration, err := time.ParseDuration(cfg.Expiry)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}
		expires := time.Now().Add(duration)
		session.ExpiresAt = expires

		session, err = cfg.Adapter.RefreshSession(c, session)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		cookieValue := &fiber.Cookie{
			Name:     cfg.SessionCookieName(),
			Value:    session.SessionToken,
			HTTPOnly: true,
			SameSite: cfg.CookieSameSite,
			Expires:  expires,
			Path:     cfg.CookiePath,
			Secure:   cfg.CookieSecure,
		}

		c.Cookie(cookieValue)

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
	return func(c fiber.Ctx) error {
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

		intent, err := provider.BeginAuth(c, cfg.Adapter, state, &Params{ctx: c})
		if err != nil {
			return err
		}

		url, err := intent.GetAuthURL()
		if err != nil {
			return err
		}

		cookie := &fiber.Cookie{
			Name:     cfg.CodeVerifierCookieName(),
			Value:    intent.CodeVerifier(),
			Path:     "/",
			MaxAge:   300,
			Secure:   utilx.NotEqual(cfg.Environment, Development),
			HTTPOnly: true,
		}
		c.Cookie(cookie)

		return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(url)
	}
}

// Handler is the interface for defining handlers for the middleware.
type Handler interface {
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
	return func(c fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		p := c.Params(provider)
		if p == "" {
			return cfg.ErrorHandler(c, ErrMissingProviderName)
		}

		provider, err := providers.GetProvider(p)
		if err != nil {
			return cfg.ErrorHandler(c, ErrMissingProviderName)
		}

		codeVerifier, err := CodeVerifierFromCookie(c, cfg)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		user, err := provider.CompleteAuth(c, cfg.Adapter, &Params{ctx: c, codeVerifier: codeVerifier})
		if err != nil {
			return cfg.ErrorHandler(c, ErrMissingUser)
		}

		duration, err := time.ParseDuration(cfg.Expiry)
		if err != nil {
			return cfg.ErrorHandler(c, ErrMissingSession)
		}
		expires := time.Now().Add(duration)

		session, err := cfg.Adapter.CreateSession(c, user.ID, expires)
		if err != nil {
			return cfg.ErrorHandler(c, ErrMissingSession)
		}

		cookieValue := &fiber.Cookie{
			Name:     cfg.SessionCookieName(),
			Value:    session.SessionToken,
			HTTPOnly: true,
			SameSite: cfg.CookieSameSite,
			Secure:   cfg.CookieSecure,
			Expires:  expires,
			Domain:   cfg.CookieDomain,
			Path:     "/",
		}

		c.Vary(fiber.HeaderCookie)
		c.Cookie(cookieValue)

		return cfg.CompletionFilter(c)
	}
}

// NewCompleteAuthHandler creates a new middleware handler to complete authentication.
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
	return func(c fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		token, err := cfg.Extractor(c)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		err = cfg.Adapter.DeleteSession(c, token)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		c.ClearCookie(cfg.SessionCookieName())

		return cfg.CompletionFilter(c)
	}
}

// Protect is a middleware that protects routes by checking for a valid session.
func Protect(config ...Config) fiber.Handler {
	cfg := configDefault(config...)
	return func(c fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		if ValidSession(c) {
			return c.Next()
		}

		u, err := url.Parse(cfg.LoginURL)
		if err != nil {
			return c.Next()
		}

		q := u.Query()
		q.Set("redirect_uri", c.FullURL())
		u.RawQuery = q.Encode()

		return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(u.String())
	}
}

// Session is the default handler to attach the session to the context.
func Session(config ...Config) fiber.Handler {
	cfg := configDefault(config...)
	return func(c fiber.Ctx) error {
		token, err := cfg.Extractor(c)
		if err != nil {
			return c.Next()
		}

		session, err := cfg.Adapter.GetSession(c, token)
		if err != nil {
			return c.Next()
		}

		if !session.IsValid() {
			return c.Next()
		}

		duration, err := time.ParseDuration(cfg.Expiry)
		if err != nil {
			return c.Next()
		}
		expires := time.Now().Add(duration)
		session.ExpiresAt = expires

		session, err = cfg.Adapter.RefreshSession(c, session)
		if err != nil {
			return c.Next()
		}

		cookieValue := &fiber.Cookie{
			Name:     cfg.SessionCookieName(),
			Value:    session.SessionToken,
			HTTPOnly: true,
			SameSite: cfg.CookieSameSite,
			Expires:  expires,
			Path:     cfg.CookiePath,
			Secure:   cfg.CookieSecure,
			Domain:   cfg.CookieDomain,
		}

		c.Cookie(cookieValue)

		c.Locals(tokenKey, session.ID)
		c.Locals(sessionKey, session)
		c.Locals(userIDKey, session.UserID)

		return c.Next()
	}
}

// ProtectedHandler returns a new default protected handler.
func ProtectedHandler(handler fiber.Handler, config ...Config) fiber.Handler {
	cfg := configDefault(config...)
	return func(c fiber.Ctx) error {
		if cfg.Next != nil && cfg.Next(c) {
			return c.Next()
		}

		if ValidSession(c) {
			return handler(c)
		}

		u, err := url.Parse(cfg.LoginURL)
		if err != nil {
			return c.Next()
		}

		q := u.Query()
		q.Set("redirect_uri", c.FullURL())
		u.RawQuery = q.Encode()

		return c.Redirect().Status(fiber.StatusTemporaryRedirect).To(u.String())
	}
}

// GetStateFromContext return the state that is returned during the callback.
func GetStateFromContext(ctx fiber.Ctx) string {
	return ctx.Query(state)
}

// ContextWithProvider returns a new request context containing the provider.
func ContextWithProvider(ctx fiber.Ctx, provider string) fiber.Ctx {
	ctx.Set(fmt.Sprint(providerKey), provider)

	return ctx
}

// SessionFromContext returns the session from the request context.
func SessionFromContext(c fiber.Ctx) (adapters.GothSession, error) {
	session, ok := c.Locals(sessionKey).(adapters.GothSession)
	if !ok {
		return adapters.GothSession{}, ErrMissingSession
	}

	return session, nil
}

// ValidSession returns true if the session is valid.
func ValidSession(c fiber.Ctx) bool {
	_, ok := c.Locals(sessionKey).(adapters.GothSession)
	return ok
}

// Config caputes the configuration for running the goth middleware.
type Config struct {
	// Next defines a function to skip this middleware when returned true.
	Next func(c fiber.Ctx) bool

	// BeginAuthHandler is the handler to start authentication.
	BeginAuthHandler Handler

	// CompleteAuthHandler is the handler to complete the authentication.
	CompleteAuthHandler Handler

	// LogoutHandler is the handler to logout.
	LogoutHandler Handler

	// SessionHandler is the handler to manage the session.
	SessionHandler Handler

	// IndexHandler is the handler to display the index.
	IndexHandler fiber.Handler

	// CompletionFilter that is executed when responses need to returned.
	CompletionFilter func(c fiber.Ctx) error

	// Secret is the secret used to sign the session.
	Secret string

	// Expiry is the duration that the session is valid for.
	Expiry string

	// CookiePrefix is the prefix of the cookies used to store session data.
	CookiePrefix string

	// CookieSameSite is the SameSite attribute of the cookie.
	CookieSameSite string

	// CookiePath is the path of the cookie.
	CookiePath string

	// CookieDomain is the domain of the cookie.
	CookieDomain string

	// CookieHTTPOnly is the HTTPOnly attribute of the cookie.
	CookieHTTPOnly bool

	// CookieSecure is the Secure attribute of the cookie.
	CookieSecure bool

	// Encryptor is the function used to encrypt the session.
	Encryptor func(decryptedString, key string) (string, error)

	// Decryptor is the function used to decrypt the session.
	Decryptor func(encryptedString, key string) (string, error)

	// Adapter is the adapter used to store the session.
	// Adapter adapters.Adapter
	Adapter adapters.Adapter

	// LoginURL is the URL to redirect to when the user is not authenticated.
	LoginURL string

	// LogoutURL is the URL to redirect to when the user logs out.
	LogoutURL string

	// CallbackURL is the URL to redirect to when the user logs out.
	CallbackURL string

	// CompletionURL is the default url after completion
	CompletionURL string

	// ErrorHandler is executed when an error is returned from fiber.Handler.
	//
	// Optional. Default: DefaultErrorHandler
	ErrorHandler fiber.ErrorHandler

	// Extractor is the function used to extract the token from the request.
	Extractor func(c fiber.Ctx) (string, error)

	// Environment is the environment the application is running in.
	Environment Environment
}

// CookieName returns the cookie name with the prefix.
func (cfg *Config) CookieName(scope string) string {
	var s strings.Builder

	s.WriteString(cfg.CookiePrefix)
	s.WriteString(".")
	s.WriteString(scope)

	return s.String()
}

// SessionCookieName returns the session cookie name with the prefix.
func (cfg *Config) SessionCookieName() string {
	return cfg.CookieName(SessionScope)
}

// CodeVerifierCookieName returns the code verifier cookie name with the prefix.
func (cfg *Config) CodeVerifierCookieName() string {
	return cfg.CookieName(CodeVerifierScope)
}

// ConfigDefault is the default config.
var ConfigDefault = Config{
	ErrorHandler:        defaultErrorHandler,
	BeginAuthHandler:    BeginAuthHandler{},
	CompleteAuthHandler: CompleteAuthCompleteHandler{},
	LogoutHandler:       LogoutHandler{},
	SessionHandler:      SessionHandler{},
	IndexHandler:        defaultIndexHandler,
	Encryptor:           EncryptCookie,
	Decryptor:           DecryptCookie,
	Expiry:              "7h",
	Extractor:           TokenFromCookie("fiber_goth.session"),
	CookieSameSite:      "lax",
	CompletionURL:       "/",
	LoginURL:            "/login",
	LogoutURL:           "/logout",
	CallbackURL:         "/auth",
	CookiePrefix:        "fiber_goth",
	CookieSecure:        false,
	Environment:         Development,
}

// default ErrorHandler that process return error from fiber.Handler.
func defaultErrorHandler(_ fiber.Ctx, err error) error {
	return NewError(http.StatusBadRequest, err.Error())
}

// default filter for response that process default return.
func defaultCompletionFilter() fiber.Handler {
	return func(c fiber.Ctx) error {
		state, err := contextFromState(c.Query("state"))
		if err != nil {
			return NewError(http.StatusBadRequest, err.Error())
		}

		return c.Redirect().Status(http.StatusTemporaryRedirect).To(state.RedirectURL)
	}
}

// default index handler that process default return.
func defaultIndexHandler(c fiber.Ctx) error {
	if c.Path() == "/login" {
		return c.Next()
	}

	return c.Redirect().Status(http.StatusTemporaryRedirect).To("/login")
}

// Helper function to set default values
//
//nolint:gocyclo
func configDefault(config ...Config) Config {
	if len(config) < 1 {
		return ConfigDefault
	}

	// Override default config
	cfg := config[0]

	if cfg.Next == nil {
		cfg.Next = ConfigDefault.Next
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

	if cfg.CookieSameSite == "" {
		cfg.CookieSameSite = ConfigDefault.CookieSameSite
	}

	if cfg.LoginURL == "" {
		cfg.LoginURL = ConfigDefault.LoginURL
	}

	if cfg.LogoutURL == "" {
		cfg.LogoutURL = ConfigDefault.LogoutURL
	}

	if cfg.CompletionURL == "" {
		cfg.CompletionURL = ConfigDefault.CompletionURL
	}

	if cfg.CallbackURL == "" {
		cfg.CallbackURL = ConfigDefault.CallbackURL
	}

	if utilx.Empty(cfg.CookiePrefix) {
		cfg.CookiePrefix = ConfigDefault.CookiePrefix
	}

	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = ConfigDefault.ErrorHandler
	}

	if cfg.CompletionFilter == nil {
		cfg.CompletionFilter = defaultCompletionFilter()
	}

	if utilx.Empty(cfg.Environment) {
		cfg.Environment = ConfigDefault.Environment
	}

	return cfg
}

func contextFromState(state string) (*StateCtx, error) {
	if state == "" {
		return &StateCtx{}, nil
	}

	stateBytes, err := base64.URLEncoding.DecodeString(state)
	if err != nil {
		return nil, err
	}

	var s StateCtx
	if err := json.Unmarshal(stateBytes, &s); err != nil {
		return nil, err
	}

	return &s, nil
}

func stateFromContext(ctx fiber.Ctx) (string, error) {
	nonce, err := generateRandomString(64) //nolint:mnd
	if err != nil {
		return "", err
	}

	s := &StateCtx{
		Nounce:      string(nonce),
		RedirectURL: ctx.Query("redirect_uri"),
	}

	state, err := json.Marshal(s)
	if err != nil {
		return "", err
	}

	return base64.URLEncoding.EncodeToString(state), nil
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
func TokenFromContext(c fiber.Ctx) string {
	token, ok := c.Locals(tokenKey).(string)
	if !ok {
		return ""
	}

	return token
}

// TokenFromCookie returns a function that extracts token from the cookie header.
func TokenFromCookie(param string) func(c fiber.Ctx) (string, error) {
	return func(c fiber.Ctx) (string, error) {
		token := c.Cookies(param)
		if token == "" {
			return "", ErrMissingCookie
		}

		return token, nil
	}
}

// CodeVerifierFromCookie returns the code verifier from the cookie.
func CodeVerifierFromCookie(c fiber.Ctx, cfg Config) (string, error) {
	cookie := c.Cookies(cfg.CodeVerifierCookieName())
	if cookie == "" {
		return "", ErrMissingCookie
	}

	return cookie, nil
}
