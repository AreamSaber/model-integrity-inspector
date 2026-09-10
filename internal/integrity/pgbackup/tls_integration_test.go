//go:build pgbackup_integration

package pgbackup

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func requireTLSPGDump(t *testing.T) string {
	t.Helper()
	path := os.Getenv("MII_TEST_PG_DUMP")
	if path == "" || !validAbsoluteFile(path) {
		t.Fatal("pgbackup_integration requires an explicit pinned MII_TEST_PG_DUMP executable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := verifyTool(ctx, path); err != nil {
		var output bytes.Buffer
		bounded := &dumpOutput{destination: &output, limit: 256, sum: sha256.New()}
		stderr := &rejectOutput{}
		diagnostic := executeNative(ctx, nativeProcessSpec{path: path, args: []string{"--version"}, env: toolEnvironment(), dir: filepath.Dir(path), stdout: bounded, stderr: stderr})
		matches := versionLine.MatchString(strings.TrimSpace(output.String()))
		t.Fatalf("required pinned tool unavailable: %v; native=%v stdout_bytes=%d stderr_seen=%t grammar_match=%t", err, diagnostic, output.Len(), stderr.seen, matches)
	}
	return path
}

func tlsPolicyLeaf(t *testing.T, issuer tlsPolicyCA, serial int64) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate fixture endpoint key")
	}
	now := time.Now().UTC()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, issuer.cert, &key.PublicKey, issuer.key)
	if err != nil {
		t.Fatal("sign fixture endpoint certificate")
	}
	return tls.Certificate{Certificate: [][]byte{der, issuer.cert.Raw}, PrivateKey: key}
}

type tlsProbeObservation struct{ connected, startup bool }

// This is only PostgreSQL's SSLRequest negotiation followed by a real TLS
// server. It does not authenticate PostgreSQL or implement a database. Reading
// a bounded StartupMessage proves that libpq accepted the TLS peer; merely
// finishing the server's TLS handshake would not be a sufficient oracle.
func runTLSPGProbe(t *testing.T, executable string, c Connection, cert tls.Certificate, raw bool, transform func([]string) []string) (tlsProbeObservation, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal("listen for controlled TLS endpoint")
	}
	defer func() { _ = listener.Close() }()
	port := listener.Addr().(*net.TCPAddr).Port
	if port < 1 || port > 65535 {
		t.Fatal("fixture listener returned an invalid TCP port")
	}
	c.Host, c.Port = "127.0.0.1", uint16(port) // #nosec G115 -- The actual listener port was checked in [1,65535] immediately above.
	observed := make(chan tlsProbeObservation, 1)
	go func() {
		var observation tlsProbeObservation
		defer func() { observed <- observation }()
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		observation.connected = true
		defer func() { _ = conn.Close() }()
		if conn.SetDeadline(time.Now().Add(10*time.Second)) != nil {
			return
		}
		var request [8]byte
		if _, readErr := io.ReadFull(conn, request[:]); readErr != nil || binary.BigEndian.Uint32(request[:4]) != 8 || binary.BigEndian.Uint32(request[4:]) != 80877103 {
			return
		}
		if _, writeErr := conn.Write([]byte{'S'}); writeErr != nil {
			return
		}
		secured := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
		if secured.HandshakeContext(ctx) != nil {
			return
		}
		var header [4]byte
		if _, readErr := io.ReadFull(secured, header[:]); readErr != nil {
			return
		}
		length := binary.BigEndian.Uint32(header[:])
		if length < 8 || length > 8192 {
			return
		}
		body := make([]byte, length-4)
		if _, readErr := io.ReadFull(secured, body); readErr == nil && binary.BigEndian.Uint32(body[:4])>>16 == 3 {
			observation.startup = true
		}
	}()
	if raw {
		env := connectionEnvironment(c)
		if transform != nil {
			env = transform(env)
		}
		err = executeNative(ctx, nativeProcessSpec{path: executable, args: []string{"--format=custom", "--no-password"},
			env: env, dir: filepath.Dir(executable), stdout: io.Discard, stderr: &rejectOutput{}})
	} else {
		var receipt DumpReceipt
		receipt, err = Dump(ctx, executable, c, DumpRequest{Snapshot: "00000001-00000001-1", WholeDatabase: true, MaxBytes: 1 << 20}, io.Discard)
		if receipt != (DumpReceipt{}) {
			t.Fatal("TLS-only endpoint yielded a backup receipt")
		}
	}
	_ = listener.Close()
	result := <-observed
	if ctx.Err() != nil || err == nil {
		t.Fatal("TLS probe timed out or pretended incomplete PostgreSQL exchange succeeded")
	}
	return result, err
}

func TestPGBackupTLSExplicitRevocation(t *testing.T) {
	executable := requireTLSPGDump(t)
	ca := newTLSPolicyCA(t, "Native TLS Root", nil, nil)
	cert := tlsPolicyLeaf(t, ca, 42)
	dir := t.TempDir()
	c := testConnection()
	c.SSLMode, c.ChannelBinding = "verify-full", "disable"
	c.RootCertificate = writeTLSPolicyFile(t, dir, "ca.pem", ca.pem)
	clean := writeTLSPolicyFile(t, dir, "clean.crl", tlsPolicyCRL(t, ca, nil))
	revoked := writeTLSPolicyFile(t, dir, "revoked.crl", tlsPolicyCRL(t, ca, func(v *x509.RevocationList) {
		v.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(42), RevocationTime: v.ThisUpdate.Add(-time.Minute), ReasonCode: 1}}
	}))
	bad := writeTLSPolicyFile(t, dir, "bad.crl", []byte("malformed CRL fixture"))
	for _, tc := range []struct {
		name, crl string
		startup   bool
	}{
		{"explicit_none", "", true}, {"valid_crl", clean, true}, {"revoked_peer", revoked, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			candidate := c
			candidate.RevocationList = tc.crl
			observation, err := runTLSPGProbe(t, executable, candidate, cert, false, nil)
			if !observation.connected || observation.startup != tc.startup || !errors.Is(err, ErrProcess) {
				t.Fatalf("real TLS oracle connected=%t startup=%t error=%v", observation.connected, observation.startup, err)
			}
		})
	}
	// A real libpq negative control bypasses ONLY our configuration validator:
	// malformed CRL is silently ignored by 18.6. The public Dump must refuse it.
	c.RevocationList = bad
	observation, _ := runTLSPGProbe(t, executable, c, cert, true, nil)
	if !observation.startup {
		t.Fatal("pinned libpq malformed-CRL negative control did not reach startup")
	}
	for _, systemRoots := range []bool{false, true} {
		candidate := c
		if systemRoots {
			candidate.RootCertificate, candidate.RevocationList = "system", clean
		}
		observation, err := runTLSPGProbe(t, executable, candidate, cert, false, nil)
		if observation.connected || !errors.Is(err, ErrConfiguration) {
			t.Fatal("unsupported/bad CRL policy reached a native TLS endpoint")
		}
	}
}

func TestPGBackupTLSDefaultCRLIsolation(t *testing.T) {
	executable := requireTLSPGDump(t)
	ca := newTLSPolicyCA(t, "No Ambient CRL Root", nil, nil)
	cert := tlsPolicyLeaf(t, ca, 52)
	dir := t.TempDir()
	c := testConnection()
	c.SSLMode, c.ChannelBinding = "verify-full", "disable"
	c.RootCertificate = writeTLSPolicyFile(t, dir, "ca.pem", ca.pem)
	var sentinel bool
	for _, entry := range connectionEnvironment(c) {
		if entry == "PGSSLCRL="+os.DevNull {
			sentinel = true
		}
	}
	if !sentinel {
		t.Fatal("explicit absent-CRL sentinel missing from child environment")
	}
	if runtime.GOOS != "linux" {
		observation, _ := runTLSPGProbe(t, executable, c, cert, false, nil)
		if !observation.startup {
			t.Fatal("pinned libpq rejected explicit no-CRL sentinel")
		}
		t.Log("Windows native sentinel handshake verified; default root.crl negative control not performed: no real profile/APPDATA files touched")
		return
	}
	// Only this test-owned child environment points at a synthetic home; the
	// real HOME and real per-user libpq files are never changed.
	fakeHome := filepath.Join(dir, "synthetic-home")
	pgDir := filepath.Join(fakeHome, ".postgresql")
	if err := os.MkdirAll(pgDir, 0700); err != nil {
		t.Fatal("create isolated default CRL fixture directory")
	}
	writeTLSPolicyFile(t, pgDir, "root.crl", tlsPolicyCRL(t, ca, func(v *x509.RevocationList) {
		v.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(52), RevocationTime: v.ThisUpdate.Add(-time.Minute)}}
	}))
	for _, removeSentinel := range []bool{true, false} {
		observation, _ := runTLSPGProbe(t, executable, c, cert, true, func(env []string) []string {
			result := make([]string, 0, len(env)+1)
			for _, entry := range env {
				if !removeSentinel || !strings.HasPrefix(entry, "PGSSLCRL=") {
					result = append(result, entry)
				}
			}
			return append(result, "HOME="+fakeHome)
		})
		if !observation.connected || observation.startup == removeSentinel {
			t.Fatal("default CRL control/sentinel did not change actual libpq validation as expected")
		}
	}
}

func TestPGBackupTLSIssuerChainRevocation(t *testing.T) {
	executable := requireTLSPGDump(t)
	root := newTLSPolicyCA(t, "Native Chain Root", nil, nil)
	intermediate := newTLSPolicyCA(t, "Native Chain Issuer", &root, func(v *x509.Certificate) { v.SerialNumber = big.NewInt(2) })
	cert := tlsPolicyLeaf(t, intermediate, 62)
	cert.Certificate = append(cert.Certificate, root.cert.Raw)
	dir := t.TempDir()
	c := testConnection()
	c.SSLMode, c.ChannelBinding = "verify-full", "disable"
	c.RootCertificate = writeTLSPolicyFile(t, dir, "ca-chain.pem", append(bytes.Clone(root.pem), intermediate.pem...))
	issuerCRL := tlsPolicyCRL(t, intermediate, nil)
	for _, revokeIssuer := range []bool{false, true} {
		rootCRL := tlsPolicyCRL(t, root, func(v *x509.RevocationList) {
			if revokeIssuer {
				v.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: intermediate.cert.SerialNumber,
					RevocationTime: v.ThisUpdate.Add(-time.Minute), ReasonCode: 1}}
			}
		})
		c.RevocationList = writeTLSPolicyFile(t, dir, "chain.crl", append(rootCRL, issuerCRL...))
		observation, err := runTLSPGProbe(t, executable, c, cert, false, nil)
		if !observation.connected || observation.startup == revokeIssuer || !errors.Is(err, ErrProcess) {
			t.Fatal("chain-level issuer revocation did not affect native TLS validation")
		}
	}
	// Missing an issuer CRL is rejected by our complete-bundle policy rather
	// than claiming the leaf issuer's list validates the complete chain.
	c.RevocationList = writeTLSPolicyFile(t, dir, "incomplete-chain.crl", issuerCRL)
	observation, err := runTLSPGProbe(t, executable, c, cert, false, nil)
	if observation.connected || !errors.Is(err, ErrConfiguration) {
		t.Fatal("incomplete issuer CRL bundle reached the network")
	}
}
