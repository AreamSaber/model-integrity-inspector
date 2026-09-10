package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"go.yaml.in/yaml/v3"

	"model-integrity-inspector.local/mii/internal/integrity/secret"
	appruntime "model-integrity-inspector.local/mii/internal/platform/runtime"
)

const backupConfigurationHeader = "# mii.backup-config-template.v1\n"
const backupConfigurationMaxBytes = 64 << 10

// Explicit bytes are for the authenticated archive only. This is a relocation
// template, NOT the live configuration, a key inventory or a restore/startup
// authorization. The coordinator must enforce restore isolation separately.
type backupConfigurationTemplate struct {
	data   []byte
	sha256 string
}

func (backupConfigurationTemplate) String() string { return "[private backup configuration template]" }
func (v backupConfigurationTemplate) Format(w fmt.State, _ rune) {
	_, _ = io.WriteString(w, v.String())
}
func (v backupConfigurationTemplate) LogValue() slog.Value       { return slog.StringValue(v.String()) }
func (backupConfigurationTemplate) MarshalJSON() ([]byte, error) { return nil, ErrConfig }
func (backupConfigurationTemplate) MarshalYAML() (any, error)    { return nil, ErrConfig }
func (v *backupConfigurationTemplate) Bytes() []byte             { return slices.Clone(v.data) }
func (v *backupConfigurationTemplate) SHA256() string            { return v.sha256 }

// Observe the validated in-memory input without reading a file or environment.
// Only role, database driver, and version labels cross this boundary. Neither
// source paths/endpoints/env names nor Build/DSN/setup token are copied.
func newBackupConfigurationTemplate(ctx context.Context, c Config) (*backupConfigurationTemplate, error) {
	if ctx == nil {
		return nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.Validate() != nil {
		return nil, ErrConfig
	}
	previous := make([]string, len(c.PreviousMasterKeys))
	for i, ref := range c.PreviousMasterKeys {
		previous[i] = ref.Version
	}
	f, err := backupConfigurationFile(string(c.Role), c.DatabaseDriver, c.MasterKeyVersion, previous)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	data, err := backupConfigurationBytes(f)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return backupConfigurationOwned(data), nil
}

// Every non-version string is generated, including the fixed relative paths.
// Sorting previous keys never changes the independently designated active key.
func backupConfigurationFile(role, driver, active string, previous []string) (fileConfig, error) {
	if (role != string(appruntime.RoleAll) && role != string(appruntime.RoleServer) && role != string(appruntime.RoleWorker)) ||
		(driver != "sqlite" && driver != "postgres") || (driver == "sqlite" && role != string(appruntime.RoleAll)) ||
		len(previous) >= secret.MaxMasterKeyFiles {
		return fileConfig{}, ErrConfig
	}
	versions := slices.Clone(previous)
	slices.Sort(versions)
	f := fileConfig{}
	c := &f.Integrity
	c.Enabled, c.Role = true, role
	c.Listen, c.PublicOrigin = "127.0.0.1:8080", "https://restore.invalid"
	c.AllowInsecureLoopback = false
	c.Queue.Provider = "database"
	c.Database.Provider, c.Database.Path, c.Database.DSNEnv = driver, "./data/mii.db", "MII_DATABASE_DSN"
	c.Reports.Path = "./reports"
	c.Security.MasterKeySource, c.Security.MasterKeyFile, c.Security.MasterKeyVersion = "file", "./keys/master.key", active
	c.Security.SetupTokenEnv = "MII_SETUP_TOKEN"
	c.Security.PreviousMasterKeys = make([]secret.KeyFileReference, len(versions))
	refs := []secret.KeyFileReference{{Version: active, File: c.Security.MasterKeyFile}}
	for i, version := range versions {
		ref := secret.KeyFileReference{Version: version, File: fmt.Sprintf("./keys/previous-%04d.key", i+1)}
		c.Security.PreviousMasterKeys[i] = ref
		refs = append(refs, ref)
	}
	if secret.ValidateKeyFiles(active, refs) != nil {
		return fileConfig{}, ErrConfig
	}
	return f, nil
}

// Reuse the real fileConfig schema without weakening KeyFileReference's
// intentionally forbidden MarshalYAML. Only generated safe references have
// an explicit private wire form; original operator references never reach it.
func backupConfigurationBytes(f fileConfig) ([]byte, error) {
	type safeReference struct {
		Version string `yaml:"version"`
		File    string `yaml:"file"`
	}
	refs := make([]safeReference, len(f.Integrity.Security.PreviousMasterKeys))
	for i, ref := range f.Integrity.Security.PreviousMasterKeys {
		refs[i] = safeReference{ref.Version, ref.File}
	}
	f.Integrity.Security.PreviousMasterKeys = nil
	var root yaml.Node
	if root.Encode(f) != nil {
		return nil, ErrConfig
	}
	node := &root
	for _, key := range []string{"integrity", "security", "previous_master_keys"} {
		var next *yaml.Node
		for i := 0; node.Kind == yaml.MappingNode && i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				next = node.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil, ErrConfig
		}
		node = next
	}
	if node.Encode(refs) != nil {
		return nil, ErrConfig
	}
	raw, err := yaml.Marshal(&root)
	if err != nil || len(raw)+len(backupConfigurationHeader) > backupConfigurationMaxBytes {
		return nil, ErrConfig
	}
	return append([]byte(backupConfigurationHeader), raw...), nil
}

// expectedSHA256 must come from the authenticated manifest/independent anchor.
// Checking a self-supplied digest proves byte consistency, not provenance.
// Decode cannot confer startup permission or supply missing key material.
func verifyBackupConfigurationTemplate(ctx context.Context, data []byte, expectedSHA256 string) (*backupConfigurationTemplate, error) {
	if ctx == nil {
		return nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(data) > backupConfigurationMaxBytes || !bytes.HasPrefix(data, []byte(backupConfigurationHeader)) {
		return nil, ErrConfig
	}
	digest := sha256.Sum256(data)
	if expectedSHA256 != hex.EncodeToString(digest[:]) {
		return nil, ErrConfig
	}
	// Parse to a syntax tree first: aliases must not expand into typed objects.
	// The raw cap bounds parsing; the walk bounds subsequent typed allocations.
	body := data[len(backupConfigurationHeader):]
	d := yaml.NewDecoder(bytes.NewReader(body))
	var tree yaml.Node
	if d.Decode(&tree) != nil {
		return nil, ErrConfig
	}
	var extra yaml.Node
	if !errors.Is(d.Decode(&extra), io.EOF) {
		return nil, ErrConfig
	}
	count := 0
	var bounded func(*yaml.Node, int) bool
	bounded = func(n *yaml.Node, depth int) bool {
		count++
		if n == nil || depth > 16 || count > 2048 || n.Kind == yaml.AliasNode || n.Anchor != "" || len(n.Value) > 256 {
			return false
		}
		for _, child := range n.Content {
			if !bounded(child, depth+1) {
				return false
			}
		}
		return true
	}
	if !bounded(&tree, 0) {
		return nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	d = yaml.NewDecoder(bytes.NewReader(body))
	d.KnownFields(true)
	var decoded fileConfig // No defaults/environment can fill omitted fields.
	if d.Decode(&decoded) != nil {
		return nil, ErrConfig
	}
	c := decoded.Integrity
	versions := make([]string, len(c.Security.PreviousMasterKeys))
	for i, ref := range c.Security.PreviousMasterKeys {
		versions[i] = ref.Version
	}
	f, err := backupConfigurationFile(c.Role, c.Database.Provider, c.Security.MasterKeyVersion, versions)
	if err != nil {
		return nil, err
	}
	canonical, err := backupConfigurationBytes(f)
	if err != nil || !bytes.Equal(data, canonical) {
		return nil, ErrConfig
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return backupConfigurationOwned(canonical), nil
}

func backupConfigurationOwned(data []byte) *backupConfigurationTemplate {
	digest := sha256.Sum256(data)
	return &backupConfigurationTemplate{data: slices.Clone(data), sha256: hex.EncodeToString(digest[:])}
}
