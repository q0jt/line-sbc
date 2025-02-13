package sbc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"errors"
	"io/fs"
	"path/filepath"
)

//go:embed certs/*
var backupCerts embed.FS

func importServiceCert(data []byte, rel bool) (*ecdsa.PublicKey, error) {
	cert, err := loadCertificate(data)
	if err != nil {
		return nil, err
	}
	pk, err := importSGXPubKeys(rel)
	if err != nil {
		return nil, err
	}
	hash := sha256Sum(cert.RawTBSCertificate)
	if !ecdsa.VerifyASN1(pk, hash, cert.Signature) {
		return nil, errors.New("invalid cert signature")
	}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return key, nil
	}
	return nil, errors.New("sbc: internal error while importing sgx cert")
}

func importSGXPubKeys(rel bool) (*ecdsa.PublicKey, error) {
	name := "backup.security.linecorp.com.pem"
	if !rel {
		name = "backup-beta.security.linecorp.com.pem"
	}
	data, err := fs.ReadFile(backupCerts, filepath.Join("certs", name))
	if err != nil {
		return nil, err
	}
	cert, err := loadCertificate(data)
	if err != nil {
		return nil, err
	}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return key, nil
	}
	return nil, errors.New("internal error")
}

func loadCertificate(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	return x509.ParseCertificate(block.Bytes)
}
