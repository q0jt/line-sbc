package sbc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"embed"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/q0jt/line-sbc/sbc/internal/sum"
)

//go:embed certs/*
var x509CACerts embed.FS

const maxCertFileSize = 64 << 10

type caType int

const (
	caTypeSGX caType = iota + 1
	caTypeNitrokey
	caTypeYubiHSM
)

var certSumOnce = sync.OnceValue(func() error {
	return sum.Verify(x509CACerts, "certs", "certs.sum")
})

func loadServiceCertificate(name string, caType caType, rel bool) (*ecdh.PublicKey, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rc, err := io.ReadAll(io.LimitReader(f, maxCertFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(rc) > maxCertFileSize {
		return nil, errors.New("sbc: service certificate file is too large")
	}
	return importServicePubKeys(rc, caType, rel)
}

func importServicePubKeys(rawCert []byte, caType caType, rel bool) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(rawCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("sbc: failed to decode PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := verifyServiceCertificate(cert, caType, rel); err != nil {
		return nil, errors.New("sbc: invalid cert signature")
	}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return key.ECDH()
	}
	return nil, errors.New("sbc: internal error while importing service cert")
}

func verifyServiceCertificate(cert *x509.Certificate, caType caType, rel bool) error {
	ca, err := importCACert(caType, rel)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(ca); !ok {
		return errors.New("sbc: failed to import root certificate")
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return err
	}
	if ok := checkCertificateKeyUsage(cert, x509.KeyUsageKeyAgreement); !ok {
		return errors.New("sbc: incorrect key usage")
	}
	return nil
}

func importCACert(caType caType, rel bool) ([]byte, error) {
	if err := certSumOnce(); err != nil {
		return nil, err
	}

	var prefix string

	switch caType {
	case caTypeSGX:
		prefix = "backup"
	case caTypeNitrokey:
		prefix = "nitrokey.backup"
	case caTypeYubiHSM:
		prefix = "yubihsm.backup"
	}

	if !rel {
		prefix = prefix + "-" + "beta"
	}

	certSuffix := "security.linecorp.com.pem"

	name := strings.Join([]string{prefix, certSuffix}, ".")
	path := filepath.Join("certs", name)

	return fs.ReadFile(x509CACerts, path)
}

func checkCertificateKeyUsage(cert *x509.Certificate, usage x509.KeyUsage) bool {
	oidKeyUsage := asn1.ObjectIdentifier{2, 5, 29, 15}

	var hasKeyUsage bool
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(oidKeyUsage) {
			hasKeyUsage = true
			break
		}
	}
	if !hasKeyUsage {
		return true
	}

	return cert.KeyUsage&usage == usage
}
