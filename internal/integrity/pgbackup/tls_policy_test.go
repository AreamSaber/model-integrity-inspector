package pgbackup

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type tlsPolicyCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

func newTLSPolicyCA(t *testing.T, name string, parent *tlsPolicyCA, change func(*x509.Certificate)) tlsPolicyCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("generate TLS fixture key")
	}
	now := time.Now().UTC().Truncate(time.Second)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		SubjectKeyId: []byte(name)}
	if change != nil {
		change(cert)
	}
	issuer, signing := cert, key
	if parent != nil {
		issuer, signing = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, cert, issuer, &key.PublicKey, signing)
	if err != nil {
		t.Fatal("sign TLS fixture CA")
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal("parse TLS fixture CA")
	}
	return tlsPolicyCA{parsed, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

func tlsPolicyCRL(t *testing.T, ca tlsPolicyCA, change func(*x509.RevocationList)) []byte {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	list := &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	if change != nil {
		change(list)
	}
	der, err := x509.CreateRevocationList(rand.Reader, list, ca.cert, ca.key)
	if err != nil {
		t.Fatal("sign TLS fixture CRL")
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func writeTLSPolicyFile(t *testing.T, dir, name string, data []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal("write synthetic TLS fixture material")
	}
	return path
}

func TestTLSCRLCompleteIssuerPolicy(t *testing.T) {
	root := newTLSPolicyCA(t, "Root", nil, nil)
	intermediate := newTLSPolicyCA(t, "Intermediate", &root, nil)
	rootCRL, intermediateCRL := tlsPolicyCRL(t, root, nil), tlsPolicyCRL(t, intermediate, nil)
	now := time.Now().UTC()
	for _, tc := range []struct {
		name        string
		roots, crls []byte
		want        bool
	}{
		{"one_ca", root.pem, rootCRL, true},
		{"issuer_chain", append(bytes.Clone(root.pem), intermediate.pem...), append(bytes.Clone(rootCRL), intermediateCRL...), true},
		{"chain_missing_crl", append(bytes.Clone(root.pem), intermediate.pem...), rootCRL, false},
		{"unconfigured_issuer", root.pem, intermediateCRL, false},
		{"duplicate_ca", append(bytes.Clone(root.pem), root.pem...), append(bytes.Clone(rootCRL), rootCRL...), false},
		{"duplicate_crl", append(bytes.Clone(root.pem), intermediate.pem...), append(bytes.Clone(rootCRL), rootCRL...), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := validateCRLMaterial(tc.roots, tc.crls, now); got != tc.want {
				t.Fatalf("issuer policy accepted=%t want=%t", got, tc.want)
			}
		})
	}
	wrongKey := newTLSPolicyCA(t, "Root", nil, nil)
	if validateCRLMaterial(root.pem, tlsPolicyCRL(t, wrongKey, nil), now) {
		t.Fatal("same issuer name with a different signing key accepted")
	}
}

func TestTLSCRLRejectsInvalidTimeScopeAndEntries(t *testing.T) {
	ca := newTLSPolicyCA(t, "Policy", nil, nil)
	now := time.Now().UTC()
	for name, change := range map[string]func(*x509.RevocationList){
		"duplicate_number": func(v *x509.RevocationList) {
			v.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 20}, Value: []byte{2, 1, 2}}}
		},
		"expired": func(v *x509.RevocationList) {
			v.ThisUpdate = now.Add(-2 * time.Hour)
			v.NextUpdate = now.Add(-time.Hour)
		},
		"future": func(v *x509.RevocationList) { v.ThisUpdate = now.Add(time.Hour); v.NextUpdate = now.Add(2 * time.Hour) },
		"delta": func(v *x509.RevocationList) {
			v.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 27}, Critical: true, Value: []byte{2, 1, 1}}}
		},
		"indirect_or_scoped": func(v *x509.RevocationList) {
			v.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: []byte{0x30, 0}}}
		},
		"unknown_noncritical": func(v *x509.RevocationList) {
			v.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{5, 0}}}
		},
		"duplicate_serial": func(v *x509.RevocationList) {
			e := x509.RevocationListEntry{SerialNumber: big.NewInt(12), RevocationTime: v.ThisUpdate.Add(-time.Minute)}
			v.RevokedCertificateEntries = []x509.RevocationListEntry{e, e}
		},
		"future_revocation": func(v *x509.RevocationList) {
			v.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(12), RevocationTime: v.ThisUpdate.Add(time.Minute)}}
		},
		"remove_from_crl": func(v *x509.RevocationList) {
			v.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(12), RevocationTime: v.ThisUpdate.Add(-time.Minute), ReasonCode: 8}}
		},
		"entry_issuer": func(v *x509.RevocationList) {
			v.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(12), RevocationTime: v.ThisUpdate.Add(-time.Minute), ExtraExtensions: []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 29}, Critical: true, Value: []byte{0x30, 0}}}}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if validateCRLMaterial(ca.pem, tlsPolicyCRL(t, ca, change), now) {
				t.Fatal("unsupported revocation policy accepted")
			}
		})
	}
	for name, change := range map[string]func(*x509.Certificate){
		"expired_ca":   func(v *x509.Certificate) { v.NotBefore = now.Add(-2 * time.Hour); v.NotAfter = now.Add(-time.Hour) },
		"future_ca":    func(v *x509.Certificate) { v.NotBefore = now.Add(time.Hour); v.NotAfter = now.Add(2 * time.Hour) },
		"no_cert_sign": func(v *x509.Certificate) { v.KeyUsage = x509.KeyUsageCRLSign },
	} {
		t.Run(name, func(t *testing.T) {
			issuer := newTLSPolicyCA(t, name, nil, change)
			if validateCRLMaterial(issuer.pem, tlsPolicyCRL(t, issuer, nil), now) {
				t.Fatal("invalid issuer accepted")
			}
		})
	}
}

func TestTLSCRLRejectsMalformedAndBoundedFiles(t *testing.T) {
	ca := newTLSPolicyCA(t, "Files", nil, nil)
	good := tlsPolicyCRL(t, ca, nil)
	block, _ := pem.Decode(good)
	badSignature := bytes.Clone(block.Bytes)
	badSignature[len(badSignature)-1] ^= 0x01
	for _, malformed := range [][]byte{
		nil, []byte("not a CRL"), block.Bytes, append([]byte("ignored-prefix\n"), good...),
		append(bytes.Clone(good), []byte("trailing-garbage")...),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: block.Bytes}),
		pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Headers: map[string]string{"Unexpected": "header"}, Bytes: block.Bytes}),
		pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: badSignature}),
		bytes.Repeat([]byte("x"), maxTLSMaterialBytes+1), bytes.Repeat(good, maxTLSMaterialBlocks+1),
	} {
		if validateCRLMaterial(ca.pem, malformed, time.Now().UTC()) {
			t.Fatal("malformed or unbounded CRL accepted")
		}
	}
	dir := t.TempDir()
	rootPath := writeTLSPolicyFile(t, dir, "ca.pem", ca.pem)
	crlPath := writeTLSPolicyFile(t, dir, "crl.pem", good)
	c := Connection{SSLMode: "verify-full", RootCertificate: rootPath, RevocationList: crlPath}
	if !validateCRL(c) {
		t.Fatal("valid bounded CRL files refused")
	}
	exact := append(bytes.Clone(good), bytes.Repeat([]byte("\n"), maxTLSMaterialBytes-len(good))...)
	c.RevocationList = writeTLSPolicyFile(t, dir, "exact-limit.crl", exact)
	if !validateCRL(c) {
		t.Fatal("exact inclusive CRL byte bound refused")
	}
	c.RevocationList = crlPath
	c.RootCertificate = "system"
	if validateCRL(c) {
		t.Fatal("system roots silently ignored explicit CRL")
	}
	c.RootCertificate = rootPath
	c.SSLMode = "disable"
	if validateCRL(c) {
		t.Fatal("plaintext connection accepted revocation policy")
	}
	c.SSLMode = "verify-full"
	for _, path := range []string{dir, filepath.Join(dir, "absent.pem"), writeTLSPolicyFile(t, dir, "large.pem", bytes.Repeat([]byte("x"), maxTLSMaterialBytes+1)), writeTLSPolicyFile(t, dir, "bad.pem", []byte("bad"))} {
		c.RevocationList = path
		if validateCRL(c) {
			t.Fatal("bad CRL file accepted")
		}
	}
	c.RevocationList = ""
	if !validateCRL(c) {
		t.Fatal("absent explicit CRL unexpectedly rejected")
	}
}

func TestTLSCRLMetadataBounds(t *testing.T) {
	// Go's CRL encoder itself refuses oversized numbers, so exercise this
	// defense without claiming an encoder failure tested our PEM validator.
	now := time.Now().UTC()
	good := x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now.Add(-time.Minute), NextUpdate: now.Add(time.Hour)}
	if !validCRLMetadata(&good, now) || validCRLMetadata(nil, now) {
		t.Fatal("CRL metadata control invalid")
	}
	maximum := good
	maximum.Number = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 159), big.NewInt(1))
	if !validCRLMetadata(&maximum, now) {
		t.Fatal("maximum 20-octet nonnegative CRL number refused")
	}
	for _, number := range []*big.Int{nil, big.NewInt(-1), new(big.Int).Lsh(big.NewInt(1), 159), new(big.Int).Lsh(big.NewInt(1), 161)} {
		v := good
		v.Number = number
		if validCRLMetadata(&v, now) {
			t.Fatal("invalid CRL number accepted")
		}
	}
	for _, next := range []time.Time{{}, now, now.Add(-time.Second)} {
		v := good
		v.NextUpdate = next
		if validCRLMetadata(&v, now) {
			t.Fatal("invalid nextUpdate accepted")
		}
	}
}

func TestTLSCRLExtensionFraming(t *testing.T) {
	ca := newTLSPolicyCA(t, "Extension framing", nil, nil)
	encoded := tlsPolicyCRL(t, ca, func(v *x509.RevocationList) {
		v.RevokedCertificateEntries = []x509.RevocationListEntry{{SerialNumber: big.NewInt(13),
			RevocationTime: v.ThisUpdate.Add(-time.Minute), ReasonCode: 1}}
	})
	block, _ := pem.Decode(encoded)
	list, err := x509.ParseRevocationList(block.Bytes)
	if err != nil || !completeCRLExtensions(list) {
		t.Fatal("valid extension framing control failed")
	}
	// Test the post-parser boundary explicitly: the pinned Go parser need not
	// reject trailing bytes inside every recognized extension's ASN.1 value.
	for i := range list.Extensions {
		candidate := *list
		candidate.Extensions = append([]pkix.Extension(nil), list.Extensions...)
		candidate.Extensions[i].Value = append(bytes.Clone(candidate.Extensions[i].Value), 5, 0)
		if completeCRLExtensions(&candidate) {
			t.Fatal("trailing extension ASN.1 accepted")
		}
	}
	entry := list.RevokedCertificateEntries[0]
	entry.Extensions = append([]pkix.Extension(nil), entry.Extensions...)
	entry.Extensions[0].Value = append(bytes.Clone(entry.Extensions[0].Value), 5, 0)
	list.RevokedCertificateEntries = []x509.RevocationListEntry{entry}
	if completeCRLExtensions(list) {
		t.Fatal("trailing reason-code ASN.1 accepted")
	}
}
