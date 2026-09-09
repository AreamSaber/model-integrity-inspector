package pgbackup

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"io"
	"os"
	"time"
)

const maxTLSMaterialBytes = 4 << 20
const maxTLSMaterialBlocks = 32

// validateCRL does not validate the peer or replace libpq's TLS handshake. It
// prevents libpq 18.6's silent CRL-load fallback for the explicitly supported
// complete, direct-issuer PEM CRLs. Every configured CA must have exactly one
// CRL; all peer-chain issuers must be included in that configured CA bundle.
// Unknown/intermediate issuers still fail libpq's CRL_CHECK_ALL at handshake.
// Delta, indirect, partitioned and unknown extension semantics are unsupported
// and rejected, not silently treated as complete revocation information.
// The coordinator owns these operator-controlled files and must keep them
// unchanged through process completion; this function is not a file capability.
func validateCRL(c Connection) bool {
	if c.RevocationList == "" {
		return true
	}
	// libpq 18.6 does not apply sslcrl inside its system-roots branch.
	if c.RootCertificate == "system" || c.SSLMode == "disable" {
		return false
	}
	roots, ok := readTLSMaterial(c.RootCertificate)
	if !ok {
		return false
	}
	crls, ok := readTLSMaterial(c.RevocationList)
	return ok && validateCRLMaterial(roots, crls, time.Now().UTC())
}

func readTLSMaterial(path string) ([]byte, bool) {
	if !validAbsoluteFile(path) {
		return nil, false
	}
	// #nosec G304 -- Explicit operator-owned regular file, validated above and bounded below; never HTTP/DSN-selected.
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	before, err := f.Stat()
	if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxTLSMaterialBytes {
		_ = f.Close()
		return nil, false
	}
	data, readErr := io.ReadAll(io.LimitReader(f, maxTLSMaterialBytes+1))
	after, statErr := f.Stat()
	closeErr := f.Close()
	if readErr != nil || statErr != nil || closeErr != nil || len(data) > maxTLSMaterialBytes ||
		int64(len(data)) != before.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, false
	}
	return data, true
}

func decodeTLSPEM(data []byte, kind string) ([][]byte, bool) {
	if len(data) == 0 || len(data) > maxTLSMaterialBytes {
		return nil, false
	}
	var blocks [][]byte
	for len(bytes.TrimSpace(data)) != 0 {
		data = bytes.TrimSpace(data)
		// pem.Decode skips arbitrary leading garbage; reject it explicitly.
		if len(blocks) == maxTLSMaterialBlocks || !bytes.HasPrefix(data, []byte("-----BEGIN "+kind+"-----")) {
			return nil, false
		}
		block, rest := pem.Decode(data)
		if block == nil || block.Type != kind || len(block.Headers) != 0 {
			return nil, false
		}
		blocks = append(blocks, block.Bytes)
		data = rest
	}
	return blocks, len(blocks) != 0
}

func validateCRLMaterial(rootPEM, crlPEM []byte, now time.Time) bool {
	rootDER, ok := decodeTLSPEM(rootPEM, "CERTIFICATE")
	if !ok {
		return false
	}
	crlDER, ok := decodeTLSPEM(crlPEM, "X509 CRL")
	if !ok || len(rootDER) != len(crlDER) {
		return false
	}
	roots := make(map[string]*x509.Certificate, len(rootDER))
	for _, der := range rootDER {
		cert, err := x509.ParseCertificate(der)
		if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || len(cert.UnhandledCriticalExtensions) != 0 ||
			cert.KeyUsage&x509.KeyUsageCertSign == 0 || cert.KeyUsage&x509.KeyUsageCRLSign == 0 ||
			now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || len(cert.SubjectKeyId) == 0 {
			return false
		}
		issuer := string(cert.RawSubject)
		if _, duplicate := roots[issuer]; duplicate {
			return false // Cross-signed/ambiguous issuer alternatives need a separate policy.
		}
		roots[issuer] = cert
	}
	seen := make(map[string]bool, len(crlDER))
	for _, der := range crlDER {
		crl, err := x509.ParseRevocationList(der)
		if err != nil || !validCRLMetadata(crl, now) {
			return false
		}
		issuer := string(crl.RawIssuer)
		cert := roots[issuer]
		if cert == nil || seen[issuer] || !bytes.Equal(crl.AuthorityKeyId, cert.SubjectKeyId) || crl.CheckSignatureFrom(cert) != nil ||
			!completeCRLExtensions(crl) {
			return false
		}
		seen[issuer] = true
	}
	return len(seen) == len(roots)
}

func validCRLMetadata(crl *x509.RevocationList, now time.Time) bool {
	// A nonnegative DER INTEGER needs a leading zero when its top bit is set;
	// 159 value bits is the largest value that fits the RFC's 20 octets.
	return crl != nil && crl.Number != nil && crl.Number.Sign() >= 0 && crl.Number.BitLen() <= 159 &&
		!crl.ThisUpdate.IsZero() && !crl.NextUpdate.IsZero() && !now.Before(crl.ThisUpdate) && now.Before(crl.NextUpdate)
}

func completeCRLExtensions(crl *x509.RevocationList) bool {
	seenExtensions := make(map[string]bool, len(crl.Extensions))
	for _, extension := range crl.Extensions {
		// Only Authority Key Identifier and CRL Number are needed by this
		// complete direct-issuer format. In particular do not accept IDP,
		// deltaCRLIndicator, freshestCRL, or unimplemented critical semantics.
		oid := extension.Id.String()
		if extension.Critical || seenExtensions[oid] || (oid != "2.5.29.35" && oid != "2.5.29.20") {
			return false
		}
		var expected []byte
		var err error
		if oid == "2.5.29.35" {
			// The supported AKI shape is keyIdentifier only. Go's X.509
			// parser ignores trailing AKI fields; do not silently accept
			// malformed or unimplemented issuer/serial alternatives.
			expected, err = asn1.Marshal(struct {
				KeyIdentifier []byte `asn1:"tag:0"`
			}{crl.AuthorityKeyId})
		} else {
			expected, err = asn1.Marshal(crl.Number)
		}
		if err != nil || !bytes.Equal(expected, extension.Value) {
			return false
		}
		seenExtensions[oid] = true
	}
	serials := make(map[string]bool, len(crl.RevokedCertificateEntries))
	for _, entry := range crl.RevokedCertificateEntries {
		if entry.SerialNumber == nil || entry.SerialNumber.Sign() <= 0 || entry.SerialNumber.BitLen() > 159 ||
			entry.RevocationTime.IsZero() || entry.RevocationTime.After(crl.ThisUpdate) ||
			entry.ReasonCode < 0 || entry.ReasonCode == 7 || entry.ReasonCode == 8 || entry.ReasonCode > 10 {
			return false
		}
		serial := entry.SerialNumber.String()
		if serials[serial] {
			return false
		}
		serials[serial] = true
		seenEntryExtensions := make(map[string]bool, len(entry.Extensions))
		for _, extension := range entry.Extensions {
			oid := extension.Id.String()
			if extension.Critical || seenEntryExtensions[oid] || oid != "2.5.29.21" {
				return false
			}
			expected, err := asn1.Marshal(asn1.Enumerated(entry.ReasonCode))
			if err != nil || !bytes.Equal(expected, extension.Value) {
				return false
			}
			seenEntryExtensions[oid] = true
		}
	}
	return true
}
