package github

import (
	"net/http"

	"github.com/zeiss/fiber-goth/providers"
	"golang.org/x/oauth2"
)

var _ providers.Provider = (*githubProvider)(nil)

var (
	AuthURL    = "https://github.com/login/oauth/authorize"
	TokenURL   = "https://github.com/login/oauth/access_token"
	ProfileURL = "https://api.github.com/user"
	EmailURL   = "https://api.github.com/user/emails"
)

// DefaultScopes holds the default scopes used for GitHub.
var DefaultScopes = []string{"user:email", "read:user"}

type githubProvider struct {
	id           string
	name         string
	clientKey    string
	secret       string
	callbackURL  string
	profileURL   string
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
		profileURL:   ProfileURL,
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

func newConfig(p *githubProvider, scopes ...string) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.clientKey,
		ClientSecret: p.secret,
		RedirectURL:  p.callbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:  p.authURL,
			TokenURL: TokenURL,
		},
		Scopes: append([]string{}, scopes...),
	}

	return c
}
