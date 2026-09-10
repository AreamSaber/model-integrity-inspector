package tokenizer

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strconv"
	"time"
)

const InstalledArtifactSchema = "mii.tokenizer-installed.v1"
const MaxInstalledArtifactBytes = 8 << 20

const installedMagic = "MII-TOKENIZER-INSTALLED-V1\n"
const installedNoticeHash = "01e032a74984f7b521bbf668f26cb1a118cf75a662035015bdc893fbd05edebc"

//go:embed THIRD_PARTY_NOTICES.md
var installedNotices []byte

var ErrInstalledArtifact = errors.New("MI_TOKENIZER_INSTALLED_ARTIFACT_INVALID")

// InstalledRef separates the original frozen configuration identity from the
// complete carrier identity. Obtain the expected ref from a trusted backup
// anchor; a ref supplied alongside untrusted bytes does not prove provenance.
// No field grants publication, authorization, calibration or execution of code.
type InstalledRef struct {
	SchemaVersion       string
	Version             string
	Implementation      string
	ConfigurationSHA256 string
	SHA256              string
	Bytes               int64
}

func (InstalledRef) String() string               { return "[private installed tokenizer reference]" }
func (r InstalledRef) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, r.String()) }
func (r InstalledRef) LogValue() slog.Value       { return slog.StringValue(r.String()) }
func (InstalledRef) MarshalJSON() ([]byte, error) { return nil, ErrInstalledArtifact }
func (InstalledRef) MarshalYAML() (any, error)    { return nil, ErrInstalledArtifact }

// InstalledArtifact is an owned, completely verified data carrier, not a file
// path, plugin, caller-defined tokenizer or historical-code fallback. Matching
// installed implementation code is still necessary to execute the resource.
type InstalledArtifact struct {
	ref  InstalledRef
	data []byte
}

func (InstalledArtifact) String() string               { return "[private installed tokenizer artifact]" }
func (a InstalledArtifact) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, a.String()) }
func (a InstalledArtifact) LogValue() slog.Value       { return slog.StringValue(a.String()) }
func (InstalledArtifact) MarshalJSON() ([]byte, error) { return nil, ErrInstalledArtifact }
func (InstalledArtifact) MarshalYAML() (any, error)    { return nil, ErrInstalledArtifact }

func (a *InstalledArtifact) Ref() InstalledRef {
	if a == nil {
		return InstalledRef{}
	}
	return a.ref
}

func (a *InstalledArtifact) Bytes() []byte {
	if a == nil {
		return nil
	}
	return bytes.Clone(a.data)
}

// NewEngine verifies again and constructs independent BPE maps from the
// ARCHIVED rank bytes. It never calls NewBuiltin, Load, tiktoken.Get, a network,
// or the module cache. Unknown code/configuration versions fail closed.
func (a *InstalledArtifact) NewEngine(ctx context.Context) (*Engine, error) {
	if a == nil {
		return nil, ErrInstalledArtifact
	}
	return restoreInstalledArtifact(ctx, a.data, a.ref)
}

type installedMetadata struct {
	SchemaVersion, Version, Implementation, Reference string
	ConfigurationSHA256, NoticesSHA256                string
	RegexImplementation                               string
	CLPattern, OPattern                               string
	VisibleTextMode, Heuristic, InputFraming          string
	BudgetSafety                                      string
	MaxTextBytes, MaxBPEBytes, MaxBPEWork, MaxBPESpan int
	RegexTimeoutMilliseconds, ConcurrentBPE           int
}

// A distinct carrier binds implementation semantics without changing the old
// builtin config hash. Application identity/code remains the backup manifest's
// release/commit concern; this data artifact is not a substitute executable.
func installedMetadataBytes() ([]byte, error) {
	return json.Marshal(installedMetadata{
		InstalledArtifactSchema, BuiltinVersion, ImplementationVersion, "openai/tiktoken@0.14.0",
		BuiltinHash, installedNoticeHash, "github.com/dlclark/regexp2/v2@v2.5.1",
		clPattern, oPattern, "ordinary-visible-text", "unicode-byte-v1", "role+content;4-per-message+3-reply-priming;+8-json-object;compatible-or-heuristic-never-exact",
		"output:non-exact-ceil(tokens*5/4),heuristic-max(tokens,visible-bytes);input:always-ceil(reserve*5/4),heuristic-max(tokens,visible-bytes+3+4*messages+8)",
		MaxTextBytes, MaxBPEBytes, maxBPEWork, maxBPESpan, 100, 2,
	})
}

var installedPartNames = [...]string{"implementation", "configuration", "cl100k_base", "o200k_base", "notices"}
var installedPartLimits = [...]int{16 << 10, 32 << 10, 2 << 20, 4 << 20, 16 << 10}

func installedContext(ctx context.Context) error {
	if ctx == nil {
		return ErrInstalledArtifact
	}
	return ctx.Err()
}

func installedDigest(ctx context.Context, data []byte) (string, error) {
	h := sha256.New()
	for len(data) > 0 {
		if err := installedContext(ctx); err != nil {
			return "", err
		}
		n := min(len(data), 64<<10)
		_, _ = h.Write(data[:n])
		data = data[n:]
	}
	if err := installedContext(ctx); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func installedConfiguration(ctx context.Context, data []byte) (bundle, error) {
	if err := installedContext(ctx); err != nil {
		return bundle{}, err
	}
	// Equality is intentionally stronger than caller-supplied hash matching:
	// only this released configuration and its full original bytes are known.
	if !bytes.Equal(data, builtinBytes) {
		return bundle{}, ErrInstalledArtifact
	}
	hash, err := installedDigest(ctx, data)
	if err != nil {
		return bundle{}, err
	}
	if hash != BuiltinHash {
		return bundle{}, ErrInstalledArtifact
	}
	var b bundle
	if json.Unmarshal(data, &b) != nil || b.Version != BuiltinVersion || b.Implementation != ImplementationVersion || len(b.Encodings) != 2 || b.Encodings[0].ID != "cl100k_base" || b.Encodings[1].ID != "o200k_base" {
		return bundle{}, ErrInstalledArtifact
	}
	return b, nil
}

// InstalledArtifact exports the ACTUAL maps used by this Engine. No caller
// path, replacement codec, current dependency lookup or config-only stand-in
// can supply the rank files. Export leaves the running Engine untouched.
func (e *Engine) InstalledArtifact(ctx context.Context) (*InstalledArtifact, error) {
	if err := installedContext(ctx); err != nil {
		return nil, err
	}
	if e == nil || e.hash != BuiltinHash || len(e.codecs) != 2 || cap(e.work) != 2 {
		return nil, ErrInstalledArtifact
	}
	config, err := json.Marshal(e.bundle)
	if err != nil {
		return nil, ErrInstalledArtifact
	}
	config = append(config, '\n')
	b, err := installedConfiguration(ctx, config)
	if err != nil {
		return nil, err
	}
	metadata, err := installedMetadataBytes()
	if err != nil {
		return nil, ErrInstalledArtifact
	}
	noticeHash, err := installedDigest(ctx, installedNotices)
	if err != nil {
		return nil, err
	}
	if noticeHash != installedNoticeHash {
		return nil, ErrInstalledArtifact
	}
	parts := [5][]byte{metadata, config, nil, nil, installedNotices}
	for i := range 2 {
		identity := b.Encodings[i]
		codec, ok := e.codecs[identity.ID].(*boundedBPE)
		pattern := clPattern
		if i == 1 {
			pattern = oPattern
		}
		if !ok || codec == nil || codec.split == nil || codec.split.String() != pattern || codec.split.MatchTimeout != 100*time.Millisecond {
			return nil, ErrInstalledArtifact
		}
		parts[2+i], err = installedRankBytes(ctx, codec.ranks, identity, installedPartLimits[2+i])
		if err != nil {
			return nil, err
		}
	}
	data, err := encodeInstalledParts(ctx, parts)
	if err != nil {
		return nil, err
	}
	hash, err := installedDigest(ctx, data)
	if err != nil {
		return nil, err
	}
	ref := InstalledRef{InstalledArtifactSchema, b.Version, b.Implementation, e.hash, hash, int64(len(data))}
	if err := installedContext(ctx); err != nil {
		return nil, err
	}
	return &InstalledArtifact{ref: ref, data: data}, nil
}

func installedRankBytes(ctx context.Context, ranks map[string]int, identity encodingArtifact, limit int) ([]byte, error) {
	if identity.Tokens < 1 || identity.Tokens > 200000 || len(ranks) != identity.Tokens {
		return nil, ErrInstalledArtifact
	}
	ordered := make([]string, identity.Tokens)
	count := 0
	for piece, rank := range ranks {
		if count%1024 == 0 {
			if err := installedContext(ctx); err != nil {
				return nil, err
			}
		}
		count++
		if len(piece) < 1 || len(piece) > 1024 || rank < 0 || rank >= identity.Tokens || ordered[rank] != "" {
			return nil, ErrInstalledArtifact
		}
		ordered[rank] = piece
	}
	var out bytes.Buffer
	for rank, piece := range ordered {
		if rank%1024 == 0 {
			if err := installedContext(ctx); err != nil {
				return nil, err
			}
		}
		if piece == "" {
			return nil, ErrInstalledArtifact
		}
		line := base64.StdEncoding.EncodeToString([]byte(piece)) + " " + strconv.Itoa(rank) + "\n"
		if len(line) > limit-out.Len() {
			return nil, ErrLimit
		}
		_, _ = out.WriteString(line)
	}
	hash, err := installedDigest(ctx, out.Bytes())
	if err != nil {
		return nil, err
	}
	if hash != identity.SHA256 {
		return nil, ErrInstalledArtifact
	}
	return out.Bytes(), nil
}

// Fixed names/order are resource identifiers, never filesystem paths. Each
// field has uint16 name length, literal name, uint64 byte length and bytes;
// there is exactly one count byte and no padding, extension or trailing data.
func encodeInstalledParts(ctx context.Context, parts [5][]byte) ([]byte, error) {
	var out bytes.Buffer
	_, _ = out.WriteString(installedMagic)
	_ = out.WriteByte(byte(len(parts)))
	for i, part := range parts {
		if err := installedContext(ctx); err != nil {
			return nil, err
		}
		if len(part) == 0 || len(part) > installedPartLimits[i] {
			return nil, ErrLimit
		}
		name := installedPartNames[i]
		nameSize := len(name)
		if nameSize < 1 || nameSize > 65535 {
			return nil, ErrInstalledArtifact
		}
		var header [10]byte
		binary.BigEndian.PutUint16(header[:2], uint16(nameSize))
		binary.BigEndian.PutUint64(header[2:], uint64(len(part)))
		_, _ = out.Write(header[:2])
		_, _ = out.WriteString(name)
		_, _ = out.Write(header[2:])
		_, _ = out.Write(part)
	}
	if out.Len() > MaxInstalledArtifactBytes {
		return nil, ErrLimit
	}
	if err := installedContext(ctx); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decodeInstalledParts(ctx context.Context, data []byte) ([5][]byte, error) {
	var parts [5][]byte
	if len(data) > MaxInstalledArtifactBytes {
		return parts, ErrLimit
	}
	if len(data) < len(installedMagic)+1 || string(data[:len(installedMagic)]) != installedMagic || data[len(installedMagic)] != byte(len(parts)) {
		return parts, ErrInstalledArtifact
	}
	remaining := data[len(installedMagic)+1:]
	for i, name := range installedPartNames {
		if err := installedContext(ctx); err != nil {
			return [5][]byte{}, err
		}
		if len(remaining) < 2 || int(binary.BigEndian.Uint16(remaining[:2])) != len(name) {
			return [5][]byte{}, ErrInstalledArtifact
		}
		remaining = remaining[2:]
		if len(remaining) < len(name)+8 || string(remaining[:len(name)]) != name {
			return [5][]byte{}, ErrInstalledArtifact
		}
		remaining = remaining[len(name):]
		n := binary.BigEndian.Uint64(remaining[:8])
		remaining = remaining[8:]
		if n == 0 || n > 4<<20 || n > uint64(len(remaining)) {
			return [5][]byte{}, ErrInstalledArtifact
		}
		size := int(n) // The explicit 4 MiB bound above also fits a 32-bit int.
		if size > installedPartLimits[i] {
			return [5][]byte{}, ErrInstalledArtifact
		}
		parts[i], remaining = remaining[:size], remaining[size:]
	}
	if len(remaining) != 0 {
		return [5][]byte{}, ErrInstalledArtifact
	}
	if err := installedContext(ctx); err != nil {
		return [5][]byte{}, err
	}
	return parts, nil
}

func installedValidRef(ref InstalledRef, bytes int) bool {
	if ref.SchemaVersion != InstalledArtifactSchema || ref.Version != BuiltinVersion || ref.Implementation != ImplementationVersion || ref.ConfigurationSHA256 != BuiltinHash || ref.Bytes != int64(bytes) || len(ref.SHA256) != 64 {
		return false
	}
	for _, c := range ref.SHA256 {
		if c < '0' || c > '9' && c < 'a' || c > 'f' {
			return false
		}
	}
	return true
}

// VerifyInstalledArtifact checks both the externally expected identity and all
// fixed internal resource identities. Supplying a self-computed expected hash
// cannot admit a different vocabulary, pattern, implementation or notice.
func VerifyInstalledArtifact(ctx context.Context, data []byte, expected InstalledRef) (*InstalledArtifact, error) {
	if err := installedContext(ctx); err != nil {
		return nil, err
	}
	if len(data) > MaxInstalledArtifactBytes {
		return nil, ErrLimit
	}
	owned := bytes.Clone(data)
	if _, err := restoreInstalledArtifact(ctx, owned, expected); err != nil {
		return nil, err
	}
	if err := installedContext(ctx); err != nil {
		return nil, err
	}
	return &InstalledArtifact{ref: expected, data: owned}, nil
}

func restoreInstalledArtifact(ctx context.Context, data []byte, expected InstalledRef) (*Engine, error) {
	if err := installedContext(ctx); err != nil {
		return nil, err
	}
	if len(data) > MaxInstalledArtifactBytes {
		return nil, ErrLimit
	}
	if len(data) == 0 || !installedValidRef(expected, len(data)) {
		return nil, ErrInstalledArtifact
	}
	hash, err := installedDigest(ctx, data)
	if err != nil {
		return nil, err
	}
	if hash != expected.SHA256 {
		return nil, ErrInstalledArtifact
	}
	parts, err := decodeInstalledParts(ctx, data)
	if err != nil {
		return nil, err
	}
	metadata, err := installedMetadataBytes()
	if err != nil || !bytes.Equal(parts[0], metadata) || !bytes.Equal(parts[4], installedNotices) {
		return nil, ErrInstalledArtifact
	}
	noticeHash, err := installedDigest(ctx, parts[4])
	if err != nil {
		return nil, err
	}
	if noticeHash != installedNoticeHash {
		return nil, ErrInstalledArtifact
	}
	b, err := installedConfiguration(ctx, parts[1])
	if err != nil {
		return nil, err
	}
	e := &Engine{bundle: b, hash: expected.ConfigurationSHA256, codecs: make(map[string]counter, 2), work: make(chan struct{}, 2)}
	for i := range 2 {
		identity := b.Encodings[i]
		ranks, err := decodeInstalledRanks(ctx, parts[i+2], identity)
		if err != nil {
			return nil, err
		}
		codec, err := newBoundedBPE(identity.ID, ranks)
		if err != nil {
			return nil, ErrInstalledArtifact
		}
		e.codecs[identity.ID] = codec
	}
	if err := installedContext(ctx); err != nil {
		return nil, err
	}
	return e, nil
}

func decodeInstalledRanks(ctx context.Context, data []byte, identity encodingArtifact) (map[string]int, error) {
	if err := installedContext(ctx); err != nil {
		return nil, err
	}
	if identity.Tokens < 1 || identity.Tokens > 200000 || len(data) == 0 || len(data) > 4<<20 {
		return nil, ErrInstalledArtifact
	}
	ranks := make(map[string]int, identity.Tokens)
	remaining := data
	for rank := 0; rank < identity.Tokens; rank++ {
		if rank%1024 == 0 {
			if err := installedContext(ctx); err != nil {
				return nil, err
			}
		}
		end := bytes.IndexByte(remaining, '\n')
		if end < 0 || end > 1380 {
			return nil, ErrInstalledArtifact
		}
		line := remaining[:end]
		remaining = remaining[end+1:]
		space := bytes.IndexByte(line, ' ')
		if space < 1 || string(line[space+1:]) != strconv.Itoa(rank) {
			return nil, ErrInstalledArtifact
		}
		encoded := line[:space]
		piece, err := base64.StdEncoding.Strict().DecodeString(string(encoded))
		if err != nil || len(piece) == 0 || len(piece) > 1024 || base64.StdEncoding.EncodeToString(piece) != string(encoded) {
			return nil, ErrInstalledArtifact
		}
		if _, duplicate := ranks[string(piece)]; duplicate {
			return nil, ErrInstalledArtifact
		}
		ranks[string(piece)] = rank
	}
	if len(remaining) != 0 || len(ranks) != identity.Tokens {
		return nil, ErrInstalledArtifact
	}
	hash, err := installedDigest(ctx, data)
	if err != nil {
		return nil, err
	}
	if hash != identity.SHA256 {
		return nil, ErrInstalledArtifact
	}
	return ranks, nil
}
