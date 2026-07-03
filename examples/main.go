package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"sort"

	goth "github.com/zeiss/fiber-goth/v3"
	gorm_adapter "github.com/zeiss/fiber-goth/v3/adapters/gorm"
	"github.com/zeiss/fiber-goth/v3/providers"
	"github.com/zeiss/fiber-goth/v3/providers/dex"
	"github.com/zeiss/fiber-goth/v3/providers/entraid"
	"github.com/zeiss/fiber-goth/v3/providers/github"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/logger"
	"github.com/gofiber/fiber/v3/middleware/requestid"
	"github.com/spf13/cobra"
	"github.com/zeiss/pkg/logx"
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
			Host:     "localhost",
			Username: "example",
			Password: "example",
			Port:     5432, //nolint:mnd
			Database: "example",
		},
	},
}

var rootCmd = &cobra.Command{
	RunE: func(cmd *cobra.Command, _ []string) error {
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

	_, err := logx.RedirectStdLog(logx.LogSink)
	if err != nil {
		return err
	}

	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%d sslmode=disable", cfg.Flags.DB.Host, cfg.Flags.DB.Username, cfg.Flags.DB.Password, cfg.Flags.DB.Database, cfg.Flags.DB.Port)
	conn, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return err
	}

	if err := gorm_adapter.RunMigrations(conn); err != nil {
		return err
	}

	ga := gorm_adapter.New(conn)

	providers.RegisterProvider(github.New(os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_SECRET"), "http://127.0.0.1:3000/auth/github/callback"))
	providers.RegisterProvider(entraid.New(os.Getenv("ENTRAID_CLIENT_ID"), os.Getenv("ENTRAID_CLIENT_SECRET"), "http://127.0.0.1:3000/auth/entraid/callback", entraid.TenantType(os.Getenv("ENTRAID_TENANT_ID"))))
	providers.RegisterProvider(dex.New(os.Getenv("DEX_CLIENT_ID"), os.Getenv("DEX_CLIENT_SECRET"), os.Getenv("DEX_ISSUER"), os.Getenv("DEX_REDIRECT_URL")))

	m := map[string]string{
		"entraid": "EntraID",
		"github":  "Github",
		"dex":     "Dex",
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	app := fiber.New()
	app.Use(requestid.New())
	app.Use(logger.New())

	gothConfig := goth.Config{
		Adapter:        ga,
		Secret:         goth.GenerateKey(),
		CookieHTTPOnly: true,
		CookieDomain:   os.Getenv("COOKIE_DOMAIN"),
		LoginURL:       "/login/dex",
	}

	app.Use(goth.Session(gothConfig))
	app.Get("/", goth.ProtectedHandler(func(c fiber.Ctx) error {
		session, err := goth.SessionFromContext(c)
		if err != nil {
			return err
		}

		return c.JSON(session)
	}, gothConfig))
	app.Get("/session", goth.NewSessionHandler(gothConfig))
	app.Get("/login/:provider", goth.NewBeginAuthHandler(gothConfig))
	app.Get("/auth/:provider/callback", goth.NewCompleteAuthHandler(gothConfig))
	app.Get("/logout", goth.NewLogoutHandler(gothConfig))

	if err := app.Listen(cfg.Flags.Addr); err != nil {
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
