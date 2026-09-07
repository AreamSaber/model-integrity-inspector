// Command replay is a DEVELOPMENT-ONLY, local-file offline detector. It has no
// live endpoint, database, label directory, stdin, network or key-generation mode.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"time"

	"model-integrity-inspector.local/mii/internal/integrity/bundle"
	"model-integrity-inspector.local/mii/internal/integrity/probe/generator"
	"model-integrity-inspector.local/mii/internal/integrity/probe/templates"
	"model-integrity-inspector.local/mii/internal/integrity/tokenizer"
	"model-integrity-inspector.local/mii/tests/replay"
	"model-integrity-inspector.local/mii/tests/replay/localfile"
)

var errArguments = errors.New("MI_REPLAY_ARGUMENTS_INVALID")

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

type options struct {
	capture, rule, ruleHash, publicKey, manifestKey, output string
	timeout                                                 time.Duration
}

func parse(args []string) (options, error) {
	var o options
	flags := flag.NewFlagSet("replay", flag.ContinueOnError)
	flags.SetOutput(io.Discard) // Never print caller arguments, paths or parse errors.
	flags.StringVar(&o.capture, "capture", "", "")
	flags.StringVar(&o.rule, "rule", "", "")
	flags.StringVar(&o.ruleHash, "rule-sha256", "", "")
	flags.StringVar(&o.publicKey, "capture-public-key-file", "", "")
	flags.StringVar(&o.manifestKey, "manifest-key-file", "", "")
	flags.StringVar(&o.output, "output", "", "")
	flags.DurationVar(&o.timeout, "timeout", 30*time.Second, "")
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			return o, errArguments
		}
		name, _, equals := strings.Cut(strings.TrimPrefix(args[i], "--"), "=")
		if flags.Lookup(name) == nil || seen[name] {
			return o, errArguments
		}
		seen[name] = true
		if !equals {
			i++
			if i >= len(args) {
				return o, errArguments
			}
		}
	}
	if flags.Parse(args) != nil || flags.NArg() != 0 || o.capture == "" || o.rule == "" || o.ruleHash == "" || o.publicKey == "" || o.manifestKey == "" || o.output == "" || o.timeout < time.Second || o.timeout > 120*time.Second {
		return o, errArguments
	}
	return o, nil
}

func run(parent context.Context, args []string, out, errOut io.Writer) int {
	o, err := parse(args)
	if err != nil {
		_, _ = fmt.Fprintln(errOut, errArguments.Error())
		return 2
	}
	ctx, cancel := context.WithTimeout(parent, o.timeout)
	defer cancel()
	if err := execute(ctx, o); err != nil {
		code := safeError(err)
		_, _ = fmt.Fprintln(errOut, code)
		if code == replay.ErrCanceled.Error() {
			return 130
		}
		return 1
	}
	_, _ = fmt.Fprintln(out, "MI_REPLAY_OK_DEVELOPMENT_ONLY")
	return 0
}

func execute(ctx context.Context, o options) error {
	publicData, err := localfile.Read(ctx, o.publicKey, localfile.MaxTrustBytes)
	if err != nil {
		return err
	}
	defer clear(publicData)
	keyID, public, err := localfile.ParseDevelopmentCapturePublicKey(publicData)
	if err != nil {
		return err
	}
	keyData, err := localfile.Read(ctx, o.manifestKey, localfile.MaxTrustBytes)
	if err != nil {
		return err
	}
	defer clear(keyData)
	signer, err := localfile.ParseDevelopmentManifestKey(keyData)
	if err != nil {
		return err
	}
	defer signer.Destroy()
	rule, err := localfile.Read(ctx, o.rule, bundle.MaxArtifactBytes)
	if err != nil {
		return err
	}
	defer clear(rule)
	resolver, err := bundle.NewResolver()
	if err != nil {
		return replay.ErrConfiguration
	}
	runtime, err := resolver.Resolve(rule, o.ruleHash)
	if err != nil {
		return replay.ErrConfiguration
	}
	tokens, err := tokenizer.NewBuiltin()
	if err != nil {
		return replay.ErrConfiguration
	}
	template, templateHash, err := templates.Builtin().Canonical()
	if err != nil {
		return replay.ErrConfiguration
	}
	verifier, err := generator.New(template, templateHash, tokens, signer)
	if err != nil {
		return replay.ErrConfiguration
	}
	engine, err := replay.New(replay.Config{CaptureKeyID: keyID, CapturePublicKey: public, Verifier: verifier, Runtime: runtime})
	if err != nil {
		return err
	}
	capture, err := localfile.Read(ctx, o.capture, replay.MaxCaptureBytes)
	if err != nil {
		return err
	}
	defer clear(capture)
	// Only a bounded memory Reader crosses the core API. No arbitrary blocking
	// Reader, filesystem handle, upstream body pipe or URL is passed to Replay.
	prediction, err := engine.Replay(ctx, bytes.NewReader(capture))
	if err != nil {
		return err
	}
	data, err := json.Marshal(prediction)
	if err != nil {
		return replay.ErrIntegrity
	}
	defer clear(data)
	return localfile.WriteNew(ctx, o.output, data, replay.MaxPredictionBytes)
}

func safeError(err error) string {
	for _, known := range []error{replay.ErrCanceled, localfile.ErrCanceled, localfile.ErrUnsafe, localfile.ErrPermissions, localfile.ErrUnavailable, localfile.ErrExists, localfile.ErrLimit, localfile.ErrTrust, localfile.ErrFilesystem, replay.ErrConfiguration, replay.ErrIntegrity, replay.ErrLimit, replay.ErrUnsupported} {
		if errors.Is(err, known) {
			return known.Error()
		}
	}
	return "MI_REPLAY_FAILED"
}
