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
	var name string
	switch caType {
	case caTypeSGX:
		name = "backup.security.linecorp.com.pem"
		if !rel {
			name = "backup-beta.security.linecorp.com.pem"
		}
	case caTypeNitrokey:
		name = "nitrokey.backup.security.linecorp.com.pem"
		if !rel {
			name = "nitrokey.beta.backup.security.linecorp.com.pem"
		}
	case caTypeYubiHSM:
		name = "yubihsm.backup.security.linecorp.com.pem"
		if !rel {
			name = "yubihsm.backup-beta.security.linecorp.com.pem"
		}
	}
	return loadX509CACert(name)
}

func loadX509CACert(name string) ([]byte, error) {
	path := filepath.Join("certs", name)
	return fs.ReadFile(x509CACerts, path)
}
