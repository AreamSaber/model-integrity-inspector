package app

import (
	"time"

	"model-integrity-inspector.local/mii/internal/buildinfo"
	"model-integrity-inspector.local/mii/internal/identity"
	"model-integrity-inspector.local/mii/internal/integrity/analysis/scoring"
	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/domain"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
)

// Called only after prepare has successfully loaded the restricted key,
// confined report directory, schema and verified immutable builtin artifacts.
func (a *application) systemStatus(service *identity.Service, cfg Config) (*identity.SystemStatusService, error) {
	// Embedders/tests may omit the CLI-provided metadata; the linked binary's
	// real build metadata is the source, not a fabricated release/version.
	if cfg.Build == (buildinfo.Info{}) {
		cfg.Build = buildinfo.Current()
	}
	return identity.NewSystemStatusService(service, identity.SystemRuntime{Role: string(cfg.Role), Build: cfg.Build, Versions: domain.BundleVersions{Rule: bundle.BuiltinVersion, Template: templates.BuiltinVersion, Scoring: scoring.Version, Tokenizer: tokenizer.BuiltinVersion}, StartupVerifiedAt: time.Now().UTC(), LocalWorkerReady: func() bool { return a.worker != nil && a.worker.Ready() }})
}
