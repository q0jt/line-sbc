package sbc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
)

func importSGXPubKeys(name string, isRelease bool) (*ecdsa.PublicKey, error) {
	cert, err := loadCertificate(name)
	if err != nil {
		return nil, err
	}
	pk, err := importRootSGXPubKeys(isRelease)
	if err != nil {
		return nil, err
	}
	hash := sha256Sum(cert.RawTBSCertificate)
	if !ecdsa.VerifyASN1(pk, hash, cert.Signature) {
		return nil, errors.New("invalid signature")
	}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return key, nil
	}
	return nil, errors.New("sbc: internal error while importing sgx cert")
}

func importRootSGXPubKeys(isRelease bool) (*ecdsa.PublicKey, error) {
	name := "sgx-release.backup.security.linecorp.com.pem"
	if !isRelease {
		name = "sgx-beta.backup.security.linecorp.com.pem"
	}
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "certs", name)
	cert, err := loadCertificate(path)
	if err != nil {
		return nil, err
	}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return key, nil
	}
	return nil, nil
}

func loadCertificate(name string) (*x509.Certificate, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
