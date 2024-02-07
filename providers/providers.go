package providers

import (
	"errors"
	"fmt"
	"net/http"
	"time"
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

// Provider needs to be implemented for each 3rd party authentication provider.
type Provider interface {
	ID() string
	Name() string
	Type() ProviderType
	Debug(bool)
}

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
		providers[p.Name()] = p
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
