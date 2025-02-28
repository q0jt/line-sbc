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

func importServicePubKeys(data []byte, rel bool) (*ecdh.PublicKey, error) {
	cert, err := loadCertificate(data)
	if err != nil {
		return nil, err
	}
	if err := verifyServiceCert(cert, rel); err != nil {
		return nil, errors.New("sbc: invalid cert signature")
	}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return key.ECDH()
	}
	return nil, errors.New("sbc: internal error while importing sgx cert")
}

func verifyServiceCert(cert *x509.Certificate, rel bool) error {
	roots := x509.NewCertPool()
	ca, err := importSGXCACert(rel)
	if err != nil {
		return err
	}
	roots.AddCert(ca)
	opts := x509.VerifyOptions{
		Roots: roots,
	}
	if _, err := cert.Verify(opts); err != nil {
		return err
	}
	return nil
}

func importSGXCACert(rel bool) (*x509.Certificate, error) {
	name := "backup.security.linecorp.com.pem"
	if !rel {
		name = "backup-beta.security.linecorp.com.pem"
	}
	return loadX509CACert(name)
}

func importNitroCACert(rel bool) (*x509.Certificate, error) {
	name := "nitrokey.backup.security.linecorp.com.pem"
	if !rel {
		name = "nitrokey.beta.backup.security.linecorp.com.pem"
	}
	return loadX509CACert(name)
}

func loadX509CACert(name string) (*x509.Certificate, error) {
	data, err := fs.ReadFile(x509CACerts, filepath.Join("certs", name))
	if err != nil {
		return nil, err
	}
	return loadCertificate(data)
}

func loadCertificate(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	return x509.ParseCertificate(block.Bytes)
}
