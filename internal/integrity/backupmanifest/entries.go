package backupmanifest

// Entry binds one authenticated archive entry to its exact plaintext length and
// SHA-256. A restore consumer must verify these while streaming and require the
// complete set exactly once before publishing. It must not trust Kind or ID as
// filesystem paths. This plan does not itself consume or authenticate any bytes.
type Entry struct {
	Kind string
	File File
}

// Entries derives an owned, deterministic plan, including the manifest itself.
// The manifest does not contain its own hash: that hash is computed only after
// canonical encoding, avoiding a self-referential/circular archive commitment.
func Entries(m Manifest) ([]Entry, error) {
	data, sha, err := Encode(m)
	if err != nil {
		return nil, err
	}
	m = canonical(m)
	result := make([]Entry, 0, 3+len(m.Reports)+len(m.Artifacts))
	result = append(result, Entry{"manifest", File{"backup-manifest", int64(len(data)), sha}}, Entry{"database", m.Database.File}, Entry{"config", m.ConfigTemplate})
	var total = int64(len(data))
	for _, e := range result[1:] {
		total += e.File.Bytes
	}
	for _, r := range m.Reports {
		result = append(result, Entry{"report", r.File})
		total += r.File.Bytes
	}
	for _, a := range m.Artifacts {
		result = append(result, Entry{"rule", a.File})
		total += a.File.Bytes
	}
	// Encode bounds the non-manifest sum to 1 TiB; adding at most 16 MiB cannot
	// overflow int64, but it can exceed the archive's total plaintext limit.
	if total > MaxFileBytes {
		return nil, ErrLimit
	}
	return result, nil
}
