package app

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

var ErrConfig = errors.New("MI_CONFIGURATION_INVALID")

// Config is private operator input, not an API DTO. No formatting or serializer
// may expose a DSN, setup token or secret filesystem layout.
type Config struct {
	Role                  appruntime.Role
	Addr                  string
	Build                 buildinfo.Info
	PublicOrigin          string
	AllowInsecureLoopback bool
	DatabaseDriver        string
	DatabasePath          string
	DatabaseDSN           string `json:"-"`
	MasterKeyFile         string
	MasterKeyVersion      string
	SetupToken            string `json:"-"`
	ReportPath            string
}

func (Config) String() string               { return "[redacted operator configuration]" }
func (c Config) Format(w fmt.State, _ rune) { _, _ = io.WriteString(w, c.String()) }
func (Config) MarshalJSON() ([]byte, error) { return nil, ErrConfig }
func (Config) MarshalYAML() (any, error)    { return nil, ErrConfig }

type fileConfig struct {
	Integrity struct {
		Enabled               bool   `yaml:"enabled"`
		Role                  string `yaml:"role"`
		Listen                string `yaml:"listen"`
		PublicOrigin          string `yaml:"public_origin"`
		AllowInsecureLoopback bool   `yaml:"allow_insecure_loopback"`
		Queue                 struct {
			Provider string `yaml:"provider"`
		} `yaml:"queue"`
		Database struct {
			Provider string `yaml:"provider"`
			Path     string `yaml:"path"`
			DSNEnv   string `yaml:"dsn_env"`
		} `yaml:"database"`
		Reports struct {
			Path string `yaml:"path"`
		} `yaml:"reports"`
		Security struct {
			MasterKeySource  string `yaml:"master_key_source"`
			MasterKeyFile    string `yaml:"master_key_file"`
			MasterKeyVersion string `yaml:"master_key_version"`
			SetupTokenEnv    string `yaml:"setup_token_env"`
		} `yaml:"security"`
	} `yaml:"integrity"`
}

func defaultFileConfig() fileConfig {
	f := fileConfig{}
	c := &f.Integrity
	c.Enabled = true
	c.Role = "all"
	c.Listen = "127.0.0.1:8080"
	c.PublicOrigin = "http://127.0.0.1:8080"
	c.AllowInsecureLoopback = true
	c.Queue.Provider = "database"
	c.Database.Provider = "sqlite"
	c.Database.Path = "./data/mii.db"
	c.Database.DSNEnv = "MII_DATABASE_DSN"
	c.Reports.Path = "./reports"
	c.Security.MasterKeySource = "file"
	c.Security.MasterKeyFile = "./data/integrity-master.key"
	c.Security.MasterKeyVersion = "v1"
	c.Security.SetupTokenEnv = "MII_SETUP_TOKEN"
	return f
}

// LoadConfig reads at most 64 KiB of strict single-document YAML, then explicit
// environment overrides. Relative paths are relative to the chosen config file;
// with no file they are relative to the working directory. Credentials are only
// read from environment, never interpolated or accepted inline in YAML.
func LoadConfig(path string, lookup func(string) string) (Config, error) {
	if lookup == nil {
		lookup = os.Getenv
	}
	f := defaultFileConfig()
	base, err := os.Getwd()
	if err != nil {
		return Config{}, ErrConfig
	}
	if path != "" {
		abs, err := filepath.Abs(path)
		if err != nil {
			return Config{}, ErrConfig
		}
		// #nosec G304 -- Explicit operator-selected configuration, not an HTTP path; bounded read and strict decode below.
		file, err := os.Open(abs)
		if err != nil {
			return Config{}, ErrConfig
		}
		data, readErr := io.ReadAll(io.LimitReader(file, (64<<10)+1))
		closeErr := file.Close()
		if readErr != nil || closeErr != nil || len(data) > 64<<10 {
			return Config{}, ErrConfig
		}
		decoder := yaml.NewDecoder(strings.NewReader(string(data)))
		decoder.KnownFields(true)
		if err := decoder.Decode(&f); err != nil {
			return Config{}, ErrConfig
		}
		var extra any
		if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
			return Config{}, ErrConfig
		}
		base = filepath.Dir(abs)
	}
	c := f.Integrity
	if !c.Enabled || c.Queue.Provider != "database" || c.Security.MasterKeySource != "file" {
		return Config{}, ErrConfig
	}
	role, err := appruntime.ParseRole(valueOr(lookup("APP_ROLE"), c.Role))
	if err != nil {
		return Config{}, ErrConfig
	}
	out := Config{Role: role, Addr: valueOr(lookup("MII_ADDR"), c.Listen), PublicOrigin: valueOr(lookup("MII_PUBLIC_ORIGIN"), c.PublicOrigin), AllowInsecureLoopback: c.AllowInsecureLoopback,
		DatabaseDriver: valueOr(lookup("MII_DATABASE_DRIVER"), c.Database.Provider), DatabasePath: valueOr(lookup("MII_DATABASE_PATH"), c.Database.Path), DatabaseDSN: lookup(c.Database.DSNEnv),
		MasterKeyFile: valueOr(lookup("MII_MASTER_KEY_FILE"), c.Security.MasterKeyFile), MasterKeyVersion: valueOr(lookup("MII_MASTER_KEY_VERSION"), c.Security.MasterKeyVersion), SetupToken: lookup(c.Security.SetupTokenEnv), ReportPath: c.Reports.Path}
	if value := lookup("MII_ALLOW_INSECURE_LOOPBACK"); value != "" {
		b, err := strconv.ParseBool(value)
		if err != nil {
			return Config{}, ErrConfig
		}
		out.AllowInsecureLoopback = b
	}
	for _, path := range []*string{&out.DatabasePath, &out.MasterKeyFile, &out.ReportPath} {
		if *path == "" {
			return Config{}, ErrConfig
		}
		if !filepath.IsAbs(*path) {
			*path = filepath.Join(base, *path)
		}
		*path = filepath.Clean(*path)
	}
	if err := out.Validate(); err != nil {
		return Config{}, err
	}
	return out, nil
}

func valueOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func (c Config) Validate() error {
	components := c.Role.Components()
	if !components.Server && !components.Worker {
		return ErrConfig
	}
	if c.DatabaseDriver != "sqlite" && c.DatabaseDriver != "postgres" {
		return ErrConfig
	}
	if c.DatabaseDriver == "sqlite" && (c.Role != appruntime.RoleAll || c.DatabasePath == "" || strings.ContainsAny(c.DatabasePath, "?\x00")) {
		return ErrConfig
	}
	if c.DatabaseDriver == "postgres" && c.DatabaseDSN == "" {
		return ErrConfig
	}
	if c.MasterKeyFile == "" || c.MasterKeyVersion == "" || c.ReportPath == "" {
		return ErrConfig
	}
	host, port, err := net.SplitHostPort(c.Addr)
	if err != nil {
		return ErrConfig
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return ErrConfig
	}
	u, err := url.Parse(c.PublicOrigin)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return ErrConfig
	}
	if u.Scheme != "https" {
		listenIP, e1 := netip.ParseAddr(host)
		originIP, e2 := netip.ParseAddr(u.Hostname())
		if u.Scheme != "http" || !c.AllowInsecureLoopback || e1 != nil || e2 != nil || !listenIP.IsLoopback() || !originIP.IsLoopback() {
			return ErrConfig
		}
	}
	if c.SetupToken != "" && (len(c.SetupToken) < 32 || len(c.SetupToken) > 256) {
		return ErrConfig
	}
	return nil
}
