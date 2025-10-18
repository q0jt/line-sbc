package sbc

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/q0jt/line-sbc/sbc/internal/sum"
)

//go:embed certs/*
var x509CACerts embed.FS

type caType int

const (
	caTypeSGX = iota + 1
	caTypeNitrokey
	caTypeYubiHSM
)

func importServicePubKeys(data []byte, caType caType, rel bool) (*ecdh.PublicKey, error) {
	block, _ := pem.Decode(data)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := verifyServiceCert(cert, caType, rel); err != nil {
		return nil, errors.New("sbc: invalid cert signature")
	}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return key.ECDH()
	}
	return nil, errors.New("sbc: internal error while importing service cert")
}

func verifyServiceCert(cert *x509.Certificate, caType caType, rel bool) error {
	roots := x509.NewCertPool()
	ca, err := importCACert(caType, rel)
	if err != nil {
		return err
	}
	if ok := roots.AppendCertsFromPEM(ca); !ok {
		return errors.New("sbc: failed to import root certificate")
	}
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return err
	}
	return nil
}

func importCACert(caType caType, rel bool) ([]byte, error) {
	err := sum.Verify(x509CACerts, "certs", "certs.sum")
	if err != nil {
		return nil, err
	}

	certSuffix := "security.linecorp.com.pem"

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

	name := strings.Join([]string{prefix, certSuffix}, ".")

	path := filepath.Join("certs", name)

	return fs.ReadFile(x509CACerts, path)
}
