package github

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/zeiss/fiber-goth/adapters"
	"github.com/zeiss/fiber-goth/providers"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var _ providers.Provider = (*githubProvider)(nil)

var (
	AuthURL  = "https://github.com/login/oauth/authorize"
	TokenURL = "https://github.com/login/oauth/access_token"
	UserURL  = "https://api.github.com/user"
	EmailURL = "https://api.github.com/user/emails"
)

// DefaultScopes holds the default scopes used for GitHub.
var DefaultScopes = []string{"user:email", "read:user"}

type githubProvider struct {
	id           string
	name         string
	clientKey    string
	secret       string
	callbackURL  string
	userURL      string
	emailURL     string
	authURL      string
	providerType providers.ProviderType
	client       *http.Client
	config       *oauth2.Config

	providers.UnimplementedProvider
}

// New creates a new GitHub provider.
func New(clientKey, secret, callbackURL string, scopes ...string) *githubProvider {
	p := &githubProvider{
		id:           "github",
		name:         "GitHub",
		clientKey:    clientKey,
		secret:       secret,
		callbackURL:  callbackURL,
		userURL:      UserURL,
		emailURL:     EmailURL,
		authURL:      AuthURL,
		providerType: providers.ProviderTypeOAuth2,
		client:       providers.DefaultClient,
	}
	p.config = newConfig(p, scopes...)

	return p
}

// ID returns the provider's ID.
func (g *githubProvider) ID() string {
	return g.id
}

// Name returns the provider's name.
func (g *githubProvider) Name() string {
	return g.name
}

// Type returns the provider's type.
func (g *githubProvider) Type() providers.ProviderType {
	return g.providerType
}

type authIntent struct {
	authURL string
}

// GetAuthURL returns the URL for the authentication end-point.
func (a *authIntent) GetAuthURL() (string, error) {
	if a.authURL == "" {
		return "", providers.ErrNoAuthURL
	}

	return a.authURL, nil
}

// BeginAuth starts the authentication process.
func (g *githubProvider) BeginAuth(ctx context.Context, adapter adapters.Adapter, state string) (providers.AuthIntent, error) {
	verifier := oauth2.GenerateVerifier()
	url := g.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))

	return &authIntent{
		authURL: url,
	}, nil
}

// CompleteAuth completes the authentication process.
func (g *githubProvider) CompleteAuth(ctx context.Context, adapter adapters.Adapter, params providers.AuthParams) (adapters.GothUser, error) {
	u := struct {
		ID       int    `json:"id"`
		Email    string `json:"email"`
		Bio      string `json:"bio"`
		Name     string `json:"name"`
		Login    string `json:"login"`
		Picture  string `json:"avatar_url"`
		Location string `json:"location"`
	}{}

	code := params.Get("code")
	if code == "" {
		return adapters.GothUser{}, adapters.ErrUnimplemented
	}

	token, err := g.config.Exchange(ctx, code)
	if err != nil {
		return adapters.GothUser{}, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", g.userURL, nil)
	if err != nil {
		return adapters.GothUser{}, err
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)

	resp, err := g.client.Do(req)
	if err != nil {
		return adapters.GothUser{}, err
	}
	defer io.Copy(io.Discard, resp.Body) // equivalent to `cp body /dev/null`
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&u)
	if err != nil {
		return adapters.GothUser{}, err
	}

	user := adapters.GothUser{
		Name:  u.Name,
		Email: u.Email,
		Image: &u.Picture,
		Accounts: []adapters.GothAccount{
			{
				Type:              adapters.AccountTypeOAuth2,
				Provider:          g.ID(),
				ProviderAccountID: adapters.StringPtr(strconv.Itoa(u.ID)),
				AccessToken:       adapters.StringPtr(token.AccessToken),
				RefreshToken:      adapters.StringPtr(token.RefreshToken),
				ExpiresAt:         adapters.TimePtr(token.Expiry),
				SessionState:      token.Extra("state").(string),
			},
		},
	}

	user, err = adapter.CreateUser(ctx, user)
	if err != nil {
		return adapters.GothUser{}, err
	}

	user, err = adapter.GetUser(ctx, user.ID)
	if err != nil {
		return adapters.GothUser{}, err
	}

	return user, nil
}

func newConfig(p *githubProvider, scopes ...string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.clientKey,
		ClientSecret: p.secret,
		RedirectURL:  p.callbackURL,
		Endpoint:     endpoints.GitHub,
		Scopes:       append(DefaultScopes, scopes...),
	}

	return c
}
