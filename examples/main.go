package main

import (
	"context"
	"fmt"
	"html/template"
	"log"
	"os"
	"sort"

	goth "github.com/zeiss/fiber-goth"
	gorm_adapter "github.com/zeiss/fiber-goth/adapters/gorm"
	"github.com/zeiss/fiber-goth/csrf"
	"github.com/zeiss/fiber-goth/providers"
	"github.com/zeiss/fiber-goth/providers/entraid"
	"github.com/zeiss/fiber-goth/providers/github"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/requestid"
	ll "github.com/katallaxie/pkg/logger"
	"github.com/spf13/cobra"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Config ...
type Config struct {
	Flags *Flags
}

// Flags ...
type Flags struct {
	Addr string
	DB   *DB
}

// DB ...
type DB struct {
	Host     string
	Username string
	Password string
	Port     int
	Database string
}

var cfg = &Config{
	Flags: &Flags{
		DB: &DB{
			Host:     "host.docker.internal",
			Username: "example",
			Password: "example",
			Port:     5432,
			Database: "example",
		},
	},
}

var rootCmd = &cobra.Command{
	RunE: func(cmd *cobra.Command, args []string) error {
		return run(cmd.Context())
	},
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.Addr, "addr", ":8080", "addr")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Host, "db-host", cfg.Flags.DB.Host, "Database host")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Database, "db-database", cfg.Flags.DB.Database, "Database name")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Username, "db-username", cfg.Flags.DB.Username, "Database user")
	rootCmd.PersistentFlags().StringVar(&cfg.Flags.DB.Password, "db-password", cfg.Flags.DB.Password, "Database password")
	rootCmd.PersistentFlags().IntVar(&cfg.Flags.DB.Port, "db-port", cfg.Flags.DB.Port, "Database port")

	rootCmd.SilenceUsage = true
}

func run(_ context.Context) error {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	ll.RedirectStdLog(ll.LogSink)

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Flags.DB.Host, cfg.Flags.DB.Username, cfg.Flags.DB.Password, cfg.Flags.DB.Database, cfg.Flags.DB.Port)
	conn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	if err := gorm_adapter.RunMigrations(conn); err != nil {
		return err
	}

	ga := gorm_adapter.New(conn)

	providers.RegisterProvider(github.New(os.Getenv("GITHUB_KEY"), os.Getenv("GITHUB_SECRET"), "http://localhost:3000/auth/github/callback"))
	providers.RegisterProvider(entraid.New(os.Getenv("ENTRAID_CLIENT_ID"), os.Getenv("ENTRAID_CLIENT_SECRET"), "http://localhost:3000/auth/entraid/callback", entraid.TenantType(os.Getenv("ENTRAID_TENANT_ID"))))

	m := map[string]string{
		"entraid": "EntraID",
		"github":  "Github",
	}
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	app := fiber.New()
	app.Use(requestid.New())
	app.Use(logger.New())

	providerIndex := &ProviderIndex{Providers: keys, ProvidersMap: m}
	engine := template.New("views")

	t, err := engine.Parse(indexTemplate)
	if err != nil {
		log.Fatal(err)
	}

	gothConfig := goth.Config{
		Adapter:        ga,
		Secret:         goth.GenerateKey(),
		CookieHTTPOnly: true,
	}

	app.Use(goth.NewProtectMiddleware(gothConfig))

	app.Get("/", func(c *fiber.Ctx) error {
		session, err := goth.SessionFromContext(c)
		if err != nil {
			return err
		}

		return c.JSON(session)
	})

	app.Get("/protected", func(c *fiber.Ctx) error {
		t, err := csrf.CsrfTokenFromContext(c)
		if err != nil {
			return err
		}

		return c.SendString(t)
	})

	app.Get("/login", func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, fiber.MIMETextHTML)
		return t.Execute(c.Response().BodyWriter(), providerIndex)
	})
	app.Get("/session", goth.NewSessionHandler(gothConfig))
	app.Use("/login/:provider", goth.NewBeginAuthHandler(gothConfig))
	app.Get("/auth/:provider/callback", goth.NewCompleteAuthHandler(gothConfig))
	app.Get("/logout", goth.NewLogoutHandler(gothConfig))

	if err := app.Listen("0.0.0.0:3000"); err != nil {
		return err
	}

	return nil
}

type ProviderIndex struct {
	Providers    []string
	ProvidersMap map[string]string
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}

var helloTemplate = `<div>Hello World</div>`

var indexTemplate = `{{range $key,$value:=.Providers}}
    <p><a href="/login/{{$value}}">Log in with {{index $.ProvidersMap $value}}</a></p>
{{end}}
<div class="container">
  <form action="/login/credentials">
    <label for="usrname">Username</label>
    <input type="text" id="usrname" name="usrname" required>

    <label for="psw">Password</label>
    <input type="password" id="psw" name="psw" pattern="(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}" title="Must contain at least one number and one uppercase and lowercase letter, and at least 8 or more characters" required>

    <input type="submit" value="Submit">
  </form>
</div>
`

var userTemplate = `
<p><a href="/logout/{{.Provider}}">logout</a></p>
<p>Name: {{.Name}} [{{.LastName}}, {{.FirstName}}]</p>
<p>Email: {{.Email}}</p>
<p>NickName: {{.NickName}}</p>
<p>Location: {{.Location}}</p>
<p>AvatarURL: {{.AvatarURL}} <img src="{{.AvatarURL}}"></p>
<p>Description: {{.Description}}</p>
<p>UserID: {{.UserID}}</p>
<p>AccessToken: {{.AccessToken}}</p>
<p>ExpiresAt: {{.ExpiresAt}}</p>
<p>RefreshToken: {{.RefreshToken}}</p>
`
