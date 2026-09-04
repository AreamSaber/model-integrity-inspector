package buildinfo

var (
	version = "0.1.0-dev"
	commit  = "unknown"
	builtAt = "unknown"
)

type Info struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	BuiltAt string `json:"built_at"`
}

func Current() Info {
	return Info{Version: version, Commit: commit, BuiltAt: builtAt}
}
