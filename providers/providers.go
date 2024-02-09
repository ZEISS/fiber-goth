package providers

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/zeiss/fiber-goth/adapters"
)

// DefaultClient is the default HTTP client used.
var DefaultClient = &http.Client{
	Transport: &http.Transport{
		MaxIdleConnsPerHost: 20,
	},
	Timeout: 10 * time.Second,
}

// ErrUnimplemented is returned when a method is not implemented.
var ErrUnimplemented = errors.New("not implemented")

// ErrNoAuthURL is returned when an AuthURL has not been set.
var ErrNoAuthURL = errors.New("an AuthURL has not been set")

// Provider needs to be implemented for each 3rd party authentication provider.
type Provider interface {
	// ID returns the provider's ID.
	ID() string
	// Debug sets the provider's debug mode.
	Debug(bool)
	// Name returns the provider's name.
	Name() string
	// Type returns the provider's type.
	Type() ProviderType
	// BeginAuth starts the authentication process.
	BeginAuth(ctx context.Context, adapter adapters.Adapter, state string) (AuthIntent, error)
	// CompleteAuth completes the authentication process.
	CompleteAuth(ctx context.Context, adapter adapters.Adapter, params AuthParams) (adapters.User, error)
}

// AuthParams is the type of authentication parameters.
type AuthParams interface {
	Get(string) string
}

// AuthIntent is the type of authentication intent.
type AuthIntent interface {
	// GetAuthURL returns the URL for the authentication end-point.
	GetAuthURL() (string, error)
}

// PrioviderType is the type of provider.
type ProviderType string

const (
	// ProviderTypeOAuth2 represents an OAuth2 account type.
	ProviderTypeOAuth2 ProviderType = "oauth2"
	// ProviderTypeOIDC represents an OIDC account type.
	ProviderTypeOIDC ProviderType = "oidc"
	// ProviderTypeSAML represents a SAML account type.
	ProviderTypeSAML ProviderType = "saml"
	// ProviderTypeEmail represents an email account type.
	ProviderTypeEmail ProviderType = "email"
	// ProviderTypeWebAuthn represents a WebAuthn account type.
	ProviderTypeWebAuthn ProviderType = "webauthn"
	// ProviderTypeUnknown represents an unknown account type.
	ProviderTypeUnknown ProviderType = "unknow"
)

// Providers is list of known/available providers.
type Providers map[string]Provider

var providers = Providers{}

// RegisterProvider adds a provider to the list of available providers for use with Goth.
func RegisterProvider(provider ...Provider) {
	for _, p := range provider {
		providers[p.ID()] = p
	}
}

// GetProviders returns a list of all the providers currently in use.
func GetProviders() Providers {
	return providers
}

// GetProvider returns a previously created provider. If Goth has not
// been told to use the named provider it will return an error.
func GetProvider(name string) (Provider, error) {
	provider := providers[name]
	if provider == nil {
		return nil, fmt.Errorf("no provider for %s exists", name)
	}

	return provider, nil
}

var _ Provider = (*UnimplementedProvider)(nil)

// UnimplementedProvider is a placeholder for a provider that has not been implemented.
type UnimplementedProvider struct {
	debug bool
}

// ID returns the provider's ID.
func (u *UnimplementedProvider) ID() string {
	return ""
}

// Name returns the provider's name.
func (u *UnimplementedProvider) Name() string {
	return ""
}

// Type returns the provider's type.
func (u *UnimplementedProvider) Type() ProviderType {
	return ProviderTypeUnknown
}

// Debug sets the provider's debug mode.
func (u *UnimplementedProvider) Debug(debug bool) {
	u.debug = debug
}

// BeginAuth starts the authentication process.
func (u *UnimplementedProvider) BeginAuth(_ context.Context, _ adapters.Adapter, state string) (AuthIntent, error) {
	return nil, ErrUnimplemented
}

// CompleteAuth completes the authentication process.
func (u *UnimplementedProvider) CompleteAuth(_ context.Context, _ adapters.Adapter, params AuthParams) (adapters.User, error) {
	return adapters.User{}, ErrUnimplemented
}
