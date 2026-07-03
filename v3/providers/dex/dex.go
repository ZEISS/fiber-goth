package dex

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/zeiss/fiber-goth/v3/adapters"
	"github.com/zeiss/fiber-goth/v3/providers"

	"github.com/zeiss/pkg/cast"
	"github.com/zeiss/pkg/utilx"
	"golang.org/x/oauth2"
)

var (
	ErrNoVerifiedPrimaryEmail = errors.New("goth: no verified primary email found")
	ErrFailedFetchUser        = errors.New("goth: no failed to fetch user")
	ErrNoName                 = errors.New("goth: user has no display name set")
	ErrAuthFailedParse        = errors.New("goth: failed to parse auth params, missing code or state")
	ErrMissingIDToken         = errors.New("goth: missing id token")
	ErrMissingVerifier        = errors.New("goth: missing verifier")
)

const NoopEmail = ""

var _ providers.Provider = (*dexProvider)(nil)

// DefaultScopes holds the default scopes used for GitHub.
var DefaultScopes = []string{"openid", "profile", "email", "groups"}

type dexProvider struct {
	id           string
	name         string
	clientID     string
	clientSecret string
	callbackURL  string
	issuer       string
	url          string
	providerType providers.ProviderType
	client       *http.Client
	config       *oauth2.Config
	scopes       []string

	providers.UnimplementedProvider
}

// Opt is a function that configures the GitHub provider.
type Opt func(*dexProvider)

// WithScopes sets the scopes for the GitHub provider.
func WithScopes(scopes ...string) Opt {
	return func(p *dexProvider) {
		p.config.Scopes = scopes
	}
}

// New creates a new GitHub provider.
func New(clientID, clientSecret, issuer, callbackURL string, opts ...Opt) providers.Provider {
	p := &dexProvider{
		id:           "dex",
		name:         "Dex",
		issuer:       issuer,
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
		providerType: providers.ProviderTypeOIDC,
		client:       providers.DefaultClient,
		scopes:       DefaultScopes,
	}

	for _, opt := range opts {
		opt(p)
	}

	p.config = newConfig(p, p.scopes...)

	return p
}

// ID returns the provider's ID.
func (d *dexProvider) ID() string {
	return d.id
}

// Name returns the provider's name.
func (d *dexProvider) Name() string {
	return d.name
}

// Type returns the provider's type.
func (d *dexProvider) Type() providers.ProviderType {
	return d.providerType
}

type authIntent struct {
	authURL      string
	codeVerifier string
}

// CodeVerifier returns the code verifier for PKCE.
func (a *authIntent) CodeVerifier() string {
	return a.codeVerifier
}

// GetAuthURL returns the URL for the authentication end-point.
func (a *authIntent) GetAuthURL() (string, error) {
	if a.authURL == "" {
		return "", providers.ErrNoAuthURL
	}

	return a.authURL, nil
}

// BeginAuth starts the authentication process.
func (g *dexProvider) BeginAuth(_ context.Context, _ adapters.Adapter, state string, _ providers.AuthParams) (providers.AuthIntent, error) {
	verifier := oauth2.GenerateVerifier()

	uri := g.config.AuthCodeURL(
		state,
		oauth2.S256ChallengeOption(verifier),
	)

	return &authIntent{
		authURL:      uri,
		codeVerifier: verifier,
	}, nil
}

// CompleteAuth completes the authentication process.
//
//nolint:gocyclo
func (g *dexProvider) CompleteAuth(ctx context.Context, adapter adapters.Adapter, params providers.AuthParams) (adapters.GothUser, error) {
	code := params.Get("code")
	if code == "" {
		return adapters.GothUser{}, ErrMissingVerifier
	}

	token, err := g.config.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", params.CodeVerifier()))
	if err != nil {
		return adapters.GothUser{}, err
	}

	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return adapters.GothUser{}, ErrMissingIDToken
	}

	provider, err := oidc.NewProvider(ctx, g.issuer)
	if err != nil {
		return adapters.GothUser{}, ErrAuthFailedParse
	}

	idTokenVerifier := provider.Verifier(&oidc.Config{ClientID: g.clientID})
	idToken, err := idTokenVerifier.Verify(ctx, rawIDToken)
	if err != nil {
		return adapters.GothUser{}, providers.ErrFailedVerifyToken
	}

	var claims struct {
		Name     string   `json:"name"`
		Email    string   `json:"email"`
		Verified bool     `json:"email_verified"`
		Groups   []string `json:"groups"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return adapters.GothUser{}, err
	}

	user := adapters.GothUser{
		Name:  claims.Name,
		Email: claims.Email,
		Accounts: []adapters.GothAccount{
			{
				Type:         adapters.AccountTypeOAuth2,
				Provider:     g.ID(),
				AccessToken:  cast.Ptr(token.AccessToken),
				RefreshToken: cast.Ptr(token.RefreshToken),
				ExpiresAt:    cast.Ptr(token.Expiry),
				IDToken:      cast.Ptr(rawIDToken),
			},
		},
	}

	if utilx.Empty(user.Email) { // TODO: verification required
		return adapters.GothUser{}, providers.ErrMissingPrimaryEmail
	}

	user, err = adapter.CreateUser(ctx, user)
	if err != nil {
		return adapters.GothUser{}, err
	}

	return user, nil
}

func newConfig(d *dexProvider, scopes ...string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     d.clientID,
		ClientSecret: d.clientSecret,
		RedirectURL:  d.callbackURL,
		Endpoint:     dexConfig(d.issuer),
		Scopes:       append(DefaultScopes, scopes...),
	}

	return c
}

func dexConfig(url string) oauth2.Endpoint {
	return oauth2.Endpoint{
		AuthURL:       fmt.Sprintf("%s/auth", strings.TrimSuffix(url, "/")),
		TokenURL:      fmt.Sprintf("%s/token", strings.TrimSuffix(url, "/")),
		DeviceAuthURL: fmt.Sprintf("%s/device/code", strings.TrimSuffix(url, "/")),
	}
}
