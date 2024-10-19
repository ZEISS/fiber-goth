package entraid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/zeiss/fiber-goth/adapters"
	"github.com/zeiss/fiber-goth/providers"
	"github.com/zeiss/pkg/cast"
	"github.com/zeiss/pkg/conv"
	"github.com/zeiss/pkg/utilx"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/endpoints"
)

var DefaultScopes = []ScopeType{OpenIDScope, ProfileScope, EmailScope, UserReadScope}

// also https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols#endpoints
const (
	GraphAPIURL string = "https://graph.microsoft.com/v1.0/"
)

type entraIdProvider struct {
	id           string
	name         string
	clientKey    string
	secret       string
	callbackURL  string
	providerType providers.ProviderType
	client       *http.Client
	config       *oauth2.Config

	providers.UnimplementedProvider
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

// New creates a new GitHub provider.
func New(clientKey, secret, callbackURL string, tenentType TenantType, scopes ...ScopeType) *entraIdProvider {
	p := &entraIdProvider{
		id:           "entraid",
		name:         "EntraID",
		clientKey:    clientKey,
		secret:       secret,
		callbackURL:  callbackURL,
		providerType: providers.ProviderTypeOAuth2,
		client:       providers.DefaultClient,
	}
	p.config = newConfig(p, utilx.IfElse(utilx.NotEmpty(tenentType), tenentType, CommonTenant), scopes...)

	return p
}

// ID returns the provider's ID.
func (g *entraIdProvider) ID() string {
	return g.id
}

// Name returns the provider's name.
func (g *entraIdProvider) Name() string {
	return g.name
}

// Type returns the provider's type.
func (g *entraIdProvider) Type() providers.ProviderType {
	return g.providerType
}

func newConfig(p *entraIdProvider, tenant TenantType, scopes ...ScopeType) *oauth2.Config {
	c := &oauth2.Config{
		ClientID:     p.clientKey,
		ClientSecret: p.secret,
		RedirectURL:  p.callbackURL,
		Endpoint:     endpoints.AzureAD(conv.String(tenant)),
		Scopes:       conv.Strings(append(DefaultScopes, scopes...)...),
	}

	return c
}

type (
	// TenantType are the well known tenant types to scope the users that can authenticate. TenantType is not an
	// exclusive list of Azure Tenants which can be used. A consumer can also use their own Tenant ID to scope
	// authentication to their specific Tenant either through the Tenant ID or the friendly domain name.
	//
	// see also https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols#endpoints
	TenantType string
)

// These are the well known Azure AD Tenants. These are not an exclusive list of all Tenants
//
// See also https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-v2-protocols#endpoints
const (
	// CommonTenant allows users with both personal Microsoft accounts and work/school accounts from Azure Active
	// Directory to sign into the application.
	CommonTenant TenantType = "common"

	// OrganizationsTenant allows only users with work/school accounts from Azure Active Directory to sign into the application.
	OrganizationsTenant TenantType = "organizations"

	// ConsumersTenant allows only users with personal Microsoft accounts (MSA) to sign into the application.
	ConsumersTenant TenantType = "consumers"
)

// BeginAuth starts the authentication process.
func (e *entraIdProvider) BeginAuth(ctx context.Context, adapter adapters.Adapter, state string, _ providers.AuthParams) (providers.AuthIntent, error) {
	url := e.config.AuthCodeURL(state)

	return &authIntent{
		authURL: url,
	}, nil
}

// CompleteAuth completes the authentication process.
// nolint:gocyclo
func (e *entraIdProvider) CompleteAuth(ctx context.Context, adapter adapters.Adapter, params providers.AuthParams) (adapters.GothUser, error) {
	u := struct {
		ID                string   `json:"id"`                // The unique identifier for the user.
		BusinessPhones    []string `json:"businessPhones"`    // The user's phone numbers.
		DisplayName       string   `json:"displayName"`       // The name displayed in the address book for the user.
		FirstName         string   `json:"givenName"`         // The first name of the user.
		JobTitle          string   `json:"jobTitle"`          // The user's job title.
		Email             string   `json:"mail"`              // The user's email address.
		MobilePhone       string   `json:"mobilePhone"`       // The user's cellphone number.
		OfficeLocation    string   `json:"officeLocation"`    // The user's physical office location.
		PreferredLanguage string   `json:"preferredLanguage"` // The user's language of preference.
		LastName          string   `json:"surname"`           // The last name of the user.
		UserPrincipalName string   `json:"userPrincipalName"` // The user's principal name.
	}{}

	code := params.Get("code")
	if code == "" {
		return adapters.GothUser{}, adapters.ErrUnimplemented
	}

	token, err := e.config.Exchange(ctx, code)
	if err != nil {
		return adapters.GothUser{}, err
	}

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf(GraphAPIURL+"me"), nil)
	if err != nil {
		return adapters.GothUser{}, err
	}
	req.Header.Add("Authorization", "Bearer "+token.AccessToken)

	resp, err := e.client.Do(req)
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
		Name:  u.DisplayName,
		Email: u.Email,
		Image: cast.Ptr(GraphAPIURL + fmt.Sprintf("users/%s/photo/$value", u.ID)),
		Accounts: []adapters.GothAccount{
			{
				Type:              adapters.AccountTypeOAuth2,
				Provider:          e.ID(),
				ProviderAccountID: cast.Ptr(u.ID),
				AccessToken:       cast.Ptr(token.AccessToken),
				RefreshToken:      cast.Ptr(token.RefreshToken),
				ExpiresAt:         cast.Ptr(token.Expiry),
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

// // RefreshTokenAvailable refresh token is provided by auth provider or not
// func (p *Provider) RefreshTokenAvailable() bool {
// 	return true
// }

// // RefreshToken get new access token based on the refresh token
// func (p *Provider) RefreshToken(refreshToken string) (*oauth2.Token, error) {
// 	token := &oauth2.Token{RefreshToken: refreshToken}
// 	ts := p.config.TokenSource(goth.ContextForClient(p.Client()), token)
// 	newToken, err := ts.Token()
// 	if err != nil {
// 		return nil, err
// 	}
// 	return newToken, err
// }
