//go:build linux && replay_netns

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"model-integrity-inspector.local/mii/tests/replay"
	"model-integrity-inspector.local/mii/tests/replay/localfile"
)

const netnsTestName = "TestOfflineReplayNetworkNamespace"

type netnsChildConfig struct {
	UID             int      `json:"uid"`
	GID             int      `json:"gid"`
	ParentNamespace string   `json:"parent_namespace"`
	ControlAddress  string   `json:"control_address"`
	Directory       string   `json:"directory"`
	Binary          string   `json:"binary"`
	FileTestBinary  string   `json:"file_test_binary"`
	Arguments       []string `json:"arguments"`
	PredictionHash  string   `json:"prediction_hash"`
}

// This test is opt-in at BUILD time, but mandatory in the quality job. It has
// no skip branch or environment fallback: an unavailable namespace is a failure.
func TestOfflineReplayNetworkNamespace(t *testing.T) {
	if os.Getenv("MII_REPLAY_NETNS_CHILD") == "1" {
		netnsChild(t)
		return
	}
	if os.Getenv("MII_REPLAY_NETNS_CHILD") != "" || os.Getuid() == 0 || os.Getuid() != os.Geteuid() || os.Getgid() != os.Getegid() {
		t.Fatal("MI_REPLAY_NETNS_FAILED_PARENT_IDENTITY")
	}
	parentNamespace := netnsIdentity(t)
	binary := builtCLI(t)
	fileTest := buildNetnsFileTests(t)
	dir := cliPrivateDir(t)
	f := syntheticFixture(t)
	args := writeFixture(t, dir, f)
	assertNetnsOwner(t, dir, os.Getuid(), true)
	for _, name := range []string{"capture.json", "rule.json", "public.json", "manifest-key.json"} {
		assertNetnsOwner(t, filepath.Join(dir, name), os.Getuid(), false)
	}
	if code, _ := invokeCLI(t, binary, args); code != 0 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CONNECTED_BASELINE")
	}
	baseline, err := localfile.Read(t.Context(), filepath.Join(dir, "prediction.json"), replay.MaxPredictionBytes)
	if err != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_BASELINE_READ")
	}
	defer clear(baseline)
	address := netnsPositiveControl(t)
	assertNetnsReachable(t, address)
	config := netnsChildConfig{os.Getuid(), os.Getgid(), parentNamespace, address, dir, binary, fileTest, args, fixtureHash(baseline)}
	data, err := json.Marshal(config)
	if err != nil || len(data) > 16<<10 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CHILD_CONFIG")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_EXECUTABLE")
	}
	for _, tool := range []string{"/usr/bin/sudo", "/usr/bin/unshare", "/usr/bin/setpriv", "/usr/bin/env"} {
		st, err := os.Stat(tool)
		if err != nil || !st.Mode().IsRegular() || st.Mode()&0o111 == 0 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_REQUIRED_TOOL")
		}
	}
	childArgs := []string{"-n", "/usr/bin/unshare", "--net", "--", "/usr/bin/setpriv",
		"--reuid=" + strconv.Itoa(config.UID), "--regid=" + strconv.Itoa(config.GID), "--clear-groups",
		"--inh-caps=-all", "--ambient-caps=-all", "--bounding-set=-all", "--no-new-privs", "--",
		"/usr/bin/env", "-i", "PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "GOTRACEBACK=none",
		"MII_REPLAY_NETNS_CHILD=1", "MII_REPLAY_NETNS_CONFIG=" + string(data), self, "-test.run=^" + netnsTestName + "$", "-test.v", "-test.timeout=90s"}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()
	// #nosec G204 -- fixed privilege tools and test-generated argv, never a shell
	// or capture-controlled command. No secrets are contained in child config.
	cmd := exec.CommandContext(ctx, "/usr/bin/sudo", childArgs...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C"}
	cmd.WaitDelay = 2 * time.Second
	output, err := cmd.CombinedOutput()
	if err != nil || bytes.Contains(output, []byte("--- SKIP:")) {
		// Only known closed stage codes are relayed, not sudo/tool/child stderr,
		// paths, environment variables, capture bytes or arbitrary test output.
		for _, code := range netnsStageCodes {
			if bytes.Contains(output, []byte(code)) {
				t.Log(code)
			}
		}
		t.Fatal("MI_REPLAY_NETNS_FAILED_ISOLATED_PROCESS")
	}
	for _, code := range netnsStageCodes[:7] {
		if bytes.Count(output, []byte(code)) != 1 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_STAGE_MISSING")
		}
		t.Log(code)
	}
	if bytes.Count(output, []byte("--- PASS: "+netnsTestName+" (")) != 1 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CHILD_NOT_RUN")
	}
	if netnsIdentity(t) != parentNamespace {
		t.Fatal("MI_REPLAY_NETNS_FAILED_PARENT_NAMESPACE_CHANGED")
	}
	assertNetnsReachable(t, address)
	assertNetnsOwner(t, filepath.Join(dir, "isolated-prediction.json"), config.UID, false)
	if got, err := localfile.Read(t.Context(), filepath.Join(dir, "isolated-prediction.json"), replay.MaxPredictionBytes); err != nil || !bytes.Equal(got, baseline) {
		t.Fatal("MI_REPLAY_NETNS_FAILED_PARENT_COMPARE")
	}
	t.Log("MI_REPLAY_NETNS_PARENT_UNCHANGED")
}

var netnsStageCodes = []string{
	"MI_REPLAY_NETNS_IDENTITY_OK", "MI_REPLAY_NETNS_TOPOLOGY_OK", "MI_REPLAY_NETNS_LOOPBACK_BLOCKED",
	"MI_REPLAY_NETNS_IP_EGRESS_BLOCKED", "MI_REPLAY_NETNS_OFFLINE_EQUAL", "MI_REPLAY_NETNS_NEGATIVES_OK", "MI_REPLAY_NETNS_ATOMIC_OK",
	"MI_REPLAY_NETNS_FAILED_CHILD_CONFIG", "MI_REPLAY_NETNS_FAILED_IDENTITY", "MI_REPLAY_NETNS_FAILED_CAPABILITIES",
	"MI_REPLAY_NETNS_FAILED_INHERITED_SOCKET", "MI_REPLAY_NETNS_FAILED_NAMESPACE", "MI_REPLAY_NETNS_FAILED_INTERFACE",
	"MI_REPLAY_NETNS_FAILED_ROUTE", "MI_REPLAY_NETNS_FAILED_NETWORK_NOT_BLOCKED", "MI_REPLAY_NETNS_FAILED_REPLAY",
	"MI_REPLAY_NETNS_FAILED_OUTPUT_COMPARE", "MI_REPLAY_NETNS_FAILED_NEGATIVE", "MI_REPLAY_NETNS_FAILED_CANCEL",
	"MI_REPLAY_NETNS_FAILED_ATOMIC_TESTS", "MI_REPLAY_NETNS_FAILED_FILE_OWNER",
}

func buildNetnsFileTests(t *testing.T) string {
	t.Helper()
	path := filepath.Join(cliPrivateDir(t), "localfile.test")
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_GO_TOOLCHAIN")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()
	// #nosec G204 -- fixed package/test compilation, before network isolation.
	cmd := exec.CommandContext(ctx, goPath, "test", "-c", "-o", path, "../../localfile")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if _, err := cmd.CombinedOutput(); err != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_FILE_TEST_BUILD")
	}
	return path
}

func netnsIdentity(t *testing.T) string {
	t.Helper()
	value, err := os.Readlink("/proc/self/ns/net")
	if err != nil || !strings.HasPrefix(value, "net:[") || !strings.HasSuffix(value, "]") || len(value) > 64 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NAMESPACE")
	}
	return value
}

func netnsPositiveControl(t *testing.T) string {
	t.Helper()
	// Only the parent listens, on ephemeral host-loopback. No external endpoint.
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CONTROL_LISTENER")
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			_, _ = io.WriteString(conn, "mii-netns-positive-control")
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Error("MI_REPLAY_NETNS_FAILED_CONTROL_CLEANUP")
		}
	})
	return listener.Addr().String()
}

func assertNetnsReachable(t *testing.T, address string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", address)
	if err != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CONTROL_UNREACHABLE")
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	data := make([]byte, len("mii-netns-positive-control"))
	if _, err := io.ReadFull(conn, data); err != nil || string(data) != "mii-netns-positive-control" {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CONTROL_PAYLOAD")
	}
}

func netnsChild(t *testing.T) {
	var config netnsChildConfig
	data := []byte(os.Getenv("MII_REPLAY_NETNS_CONFIG"))
	if len(data) == 0 || len(data) > 16<<10 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CHILD_CONFIG")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&config) != nil || config.UID < 1 || config.GID < 1 || len(config.Arguments) != 14 || len(config.PredictionHash) != 64 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CHILD_CONFIG")
	}
	if os.Getuid() != config.UID || os.Geteuid() != config.UID || os.Getgid() != config.GID || os.Getegid() != config.GID {
		t.Fatal("MI_REPLAY_NETNS_FAILED_IDENTITY")
	}
	assertNetnsPrivileges(t, config)
	t.Log(netnsStageCodes[0])
	if netnsIdentity(t) == config.ParentNamespace {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NAMESPACE")
	}
	assertNetnsTopology(t)
	t.Log(netnsStageCodes[1])
	assertNetnsBlocked(t, "tcp4", config.ControlAddress, true)
	t.Log(netnsStageCodes[2])
	// RFC 5737 / RFC 3849 documentation addresses, attempted ONLY after the
	// separate namespace, no-UP-interface and no-usable-route checks passed.
	assertNetnsBlocked(t, "tcp4", "192.0.2.1:9", false)
	assertNetnsBlocked(t, "tcp6", "[2001:db8::1]:9", false)
	t.Log(netnsStageCodes[3])
	for _, name := range []string{"capture.json", "rule.json", "public.json", "manifest-key.json"} {
		assertNetnsOwner(t, filepath.Join(config.Directory, name), config.UID, false)
	}
	output := filepath.Join(config.Directory, "isolated-prediction.json")
	args := withArg(config.Arguments, "--output", output)
	if code, _ := invokeCLI(t, config.Binary, args); code != 0 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_REPLAY")
	}
	got, err := localfile.Read(t.Context(), output, replay.MaxPredictionBytes)
	if err != nil || fixtureHash(got) != config.PredictionHash {
		t.Fatal("MI_REPLAY_NETNS_FAILED_OUTPUT_COMPARE")
	}
	assertNetnsOwner(t, output, config.UID, false)
	t.Log(netnsStageCodes[4])
	netnsNegativeCLI(t, config, args)
	t.Log(netnsStageCodes[5])
	netnsAtomicTests(t, config.FileTestBinary)
	t.Log(netnsStageCodes[6])
}

func assertNetnsPrivileges(t *testing.T, c netnsChildConfig) {
	t.Helper()
	raw, err := os.ReadFile("/proc/self/status")
	if err != nil || len(raw) > 32<<10 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_IDENTITY")
	}
	fields := map[string][]string{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.Fields(value)
		}
	}
	for key, want := range map[string]int{"Uid": c.UID, "Gid": c.GID} {
		values := fields[key]
		if len(values) != 4 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_IDENTITY")
		}
		for _, value := range values {
			if value != strconv.Itoa(want) {
				t.Fatal("MI_REPLAY_NETNS_FAILED_IDENTITY")
			}
		}
	}
	if len(fields["Groups"]) != 0 || len(fields["NoNewPrivs"]) != 1 || fields["NoNewPrivs"][0] != "1" {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CAPABILITIES")
	}
	for _, key := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		values := fields[key]
		if len(values) != 1 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_CAPABILITIES")
		}
		value, err := strconv.ParseUint(values[0], 16, 64)
		if err != nil || value != 0 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_CAPABILITIES")
		}
	}
	fds, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(fds) > 64 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_INHERITED_SOCKET")
	}
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", fd.Name()))
		if os.IsNotExist(err) {
			continue
		} // ReadDir's own now-closed directory fd.
		if err != nil || strings.HasPrefix(target, "socket:[") {
			t.Fatal("MI_REPLAY_NETNS_FAILED_INHERITED_SOCKET")
		}
	}
}

func assertNetnsTopology(t *testing.T) {
	t.Helper()
	interfaces, err := net.Interfaces()
	if err != nil || len(interfaces) != 1 || interfaces[0].Name != "lo" || interfaces[0].Flags&net.FlagUp != 0 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_INTERFACE")
	}
	for _, table := range []struct {
		path      string
		flagField int
		ipv4      bool
	}{{"/proc/net/route", 3, true}, {"/proc/net/ipv6_route", 8, false}} {
		raw, err := os.ReadFile(table.path)
		if err != nil || len(raw) > 64<<10 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_ROUTE")
		}
		for i, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if (table.ipv4 && i == 0) || strings.TrimSpace(line) == "" {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 10 {
				t.Fatal("MI_REPLAY_NETNS_FAILED_ROUTE")
			}
			flags, err := strconv.ParseUint(fields[table.flagField], 16, 32)
			// Kernel IPv6 reject routes can exist even with lo DOWN. They are
			// not a usable route: RTF_UP=1, RTF_REJECT=0x200.
			if err != nil || (flags&1 != 0 && flags&0x200 == 0) {
				t.Fatal("MI_REPLAY_NETNS_FAILED_ROUTE")
			}
		}
	}
}

func assertNetnsBlocked(t *testing.T, network, address string, loopback bool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if conn != nil {
		_ = conn.Close()
	}
	allowed := errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) || (network == "tcp6" && errors.Is(err, unix.EAFNOSUPPORT)) || (loopback && errors.Is(err, unix.ECONNREFUSED))
	if err == nil || ctx.Err() != nil || !allowed {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NETWORK_NOT_BLOCKED")
	}
}

func assertNetnsOwner(t *testing.T, path string, uid int, directory bool) {
	t.Helper()
	var st unix.Stat_t
	if unix.Lstat(path, &st) != nil || int64(st.Uid) != int64(uid) {
		t.Fatal("MI_REPLAY_NETNS_FAILED_FILE_OWNER")
	}
	if directory {
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Mode&0o7777 != 0o700 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_FILE_OWNER")
		}
	} else if st.Mode&unix.S_IFMT != unix.S_IFREG || st.Mode&0o7777 != 0o600 || st.Nlink != 1 {
		t.Fatal("MI_REPLAY_NETNS_FAILED_FILE_OWNER")
	}
}

func netnsNegativeCLI(t *testing.T, c netnsChildConfig, args []string) {
	t.Helper()
	bad := filepath.Join(c.Directory, "bad-capture.json")
	if localfile.WriteNew(t.Context(), bad, []byte(`{"invalid":"synthetic"}`), 100) != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NEGATIVE")
	}
	key, err := localfile.NewManifestSigner()
	if err != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NEGATIVE")
	}
	defer key.Destroy()
	encoded, err := localfile.EncodeDevelopmentManifestKey(key)
	if err != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NEGATIVE")
	}
	defer clear(encoded)
	keyPath := filepath.Join(c.Directory, "different-manifest-key.json")
	if localfile.WriteNew(t.Context(), keyPath, encoded, localfile.MaxTrustBytes) != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NEGATIVE")
	}
	for _, tc := range []struct{ name, flag, value string }{{"bad-capture", "--capture", bad}, {"bad-key", "--manifest-key-file", keyPath}} {
		output := filepath.Join(c.Directory, tc.name+"-output.json")
		changed := withArg(withArg(args, tc.flag, tc.value), "--output", output)
		code, message := invokeCLI(t, c.Binary, changed)
		if code == 0 || !strings.HasPrefix(message, "MI_REPLAY_") || strings.Count(message, "\n") != 1 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_NEGATIVE")
		}
		if _, err := os.Stat(output); !os.IsNotExist(err) {
			t.Fatal("MI_REPLAY_NETNS_FAILED_NEGATIVE")
		}
	}
	existing := filepath.Join(c.Directory, "existing-prediction.json")
	if localfile.WriteNew(t.Context(), existing, []byte("sentinel"), 100) != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NEGATIVE")
	}
	code, message := invokeCLI(t, c.Binary, withArg(args, "--output", existing))
	data, err := localfile.Read(t.Context(), existing, 100)
	if code == 0 || message != localfile.ErrExists.Error()+"\n" || err != nil || string(data) != "sentinel" {
		t.Fatal("MI_REPLAY_NETNS_FAILED_NEGATIVE")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Deterministic pre-start cancellation; after-Sync cancellation is tested below.
	output := filepath.Join(c.Directory, "canceled-cli.json")
	// #nosec G204 -- same previously verified test-built executable, no shell.
	cmd := exec.CommandContext(ctx, c.Binary, withArg(args, "--output", output)...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C"}
	if err := cmd.Start(); !errors.Is(err, context.Canceled) || cmd.Process != nil {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CANCEL")
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("MI_REPLAY_NETNS_FAILED_CANCEL")
	}
}

func netnsAtomicTests(t *testing.T, binary string) {
	t.Helper()
	names := []string{"TestAtomicWriteReadAndNoReplace", "TestAtomicCancelBeforePublicationLeavesNoFinal", "TestAtomicConcurrentNoReplace", "TestFileInputBoundaries", "TestSymlinkInputAndParentRejected", "TestUnixFIFOAndPermissions", "TestLinuxFilesystemPolicy"}
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Second)
	defer cancel()
	// #nosec G204 -- fixed localfile tests compiled before entering the namespace.
	cmd := exec.CommandContext(ctx, binary, "-test.run=^("+strings.Join(names, "|")+")$", "-test.v", "-test.timeout=30s")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "GOTRACEBACK=none"}
	output, err := cmd.CombinedOutput()
	if err != nil || bytes.Contains(output, []byte("--- SKIP:")) {
		t.Fatal("MI_REPLAY_NETNS_FAILED_ATOMIC_TESTS")
	}
	for _, name := range names {
		if bytes.Count(output, []byte("--- PASS: "+name+" (")) != 1 {
			t.Fatal("MI_REPLAY_NETNS_FAILED_ATOMIC_TESTS")
		}
	}
}
