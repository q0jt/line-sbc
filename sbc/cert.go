package sbc

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

const releaseBackupCert = `-----BEGIN CERTIFICATE-----
MIICijCCAi6gAwIBAgIRALhtuZun3W9aZv5uZ8sRg/0wDAYIKoZIzj0EAwIFADCB
kTELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMREwDwYDVQQHDAhTaGluanVr
dTEZMBcGA1UECgwQTElORSBDb3Jwb3JhdGlvbjEaMBgGA1UECwwRU2VjdXJpdHkg
UiZEIFRlYW0xKDAmBgNVBAMMH2NhLmJhY2t1cC5zZWN1cml0eS5saW5lY29ycC5j
b20wHhcNMjExMTA0MTYwMDAwWhcNMzExMTA0MTYwMDAwWjCBkTELMAkGA1UEBhMC
SlAxDjAMBgNVBAgMBVRva3lvMREwDwYDVQQHDAhTaGluanVrdTEZMBcGA1UECgwQ
TElORSBDb3Jwb3JhdGlvbjEaMBgGA1UECwwRU2VjdXJpdHkgUiZEIFRlYW0xKDAm
BgNVBAMMH2NhLmJhY2t1cC5zZWN1cml0eS5saW5lY29ycC5jb20wWTATBgcqhkjO
PQIBBggqhkjOPQMBBwNCAAT90jB1WStrJ/EsA4GkbXS5O53S06cq17gnc5GdP8ch
eMiviSQy59QQ3XUB6XaLwH2xAie7mE93a/XV7oUffI06o2MwYTAPBgNVHRMBAf8E
BTADAQH/MA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUb9kEckUbg847qEHFqPG6
kV73BcMwHwYDVR0jBBgwFoAUb9kEckUbg847qEHFqPG6kV73BcMwDAYIKoZIzj0E
AwIFAANIADBFAiBLLZqvc5pqJRYRlg62/TAsDyYxBXgHx9YoZ6wWHyatXwIhAJEr
/+UCi1TJxFW5n0J+0iZYnU2XdwyLT2Fjb5J/cWsK
-----END CERTIFICATE-----`

const betaBackupCert = `-----BEGIN CERTIFICATE-----
MIIClDCCAjigAwIBAgIRAJdGhR0DuKhuJBBLSLyAN5wwDAYIKoZIzj0EAwIFADCB
ljELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBVRva3lvMREwDwYDVQQHDAhTaGluanVr
dTEZMBcGA1UECgwQTElORSBDb3Jwb3JhdGlvbjEaMBgGA1UECwwRU2VjdXJpdHkg
UiZEIFRlYW0xLTArBgNVBAMMJGNhLmJhY2t1cC1iZXRhLnNlY3VyaXR5LmxpbmVj
b3JwLmNvbTAeFw0yMTExMDQxNTAwMDBaFw0zMTExMDQxNTAwMDBaMIGWMQswCQYD
VQQGEwJKUDEOMAwGA1UECAwFVG9reW8xETAPBgNVBAcMCFNoaW5qdWt1MRkwFwYD
VQQKDBBMSU5FIENvcnBvcmF0aW9uMRowGAYDVQQLDBFTZWN1cml0eSBSJkQgVGVh
bTEtMCsGA1UEAwwkY2EuYmFja3VwLWJldGEuc2VjdXJpdHkubGluZWNvcnAuY29t
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEW8PQT1Jm3/PNV+VKrTTqn1q0CvsM
8kSIJ4QeQGfVgqSyiiKyxHH0aWMDE8jEtqH9WN532AdLqJOiQaqgo5VVSKNjMGEw
DwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0OBBYEFKwzb0Vh
QbNu0epksXWFAM4MP99VMB8GA1UdIwQYMBaAFKwzb0VhQbNu0epksXWFAM4MP99V
MAwGCCqGSM49BAMCBQADSAAwRQIhAOscJ4KbfP/pKwLsd2HYFee0mABuhCQTUR3v
act3AKUxAiAQqsuL6xFQS/+VV8lWQfVV6BWAvvIidK0cPlG37i+9xQ==
-----END CERTIFICATE-----`

func importSGXPubKeys(data []byte, isRelease bool) (*ecdsa.PublicKey, error) {
	cert, err := loadCertificate(data)
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
	data := []byte(releaseBackupCert)
	if !isRelease {
		data = []byte(betaBackupCert)
	}
	cert, err := loadCertificate(data)
	if err != nil {
		return nil, err
	}
	if key, ok := cert.PublicKey.(*ecdsa.PublicKey); ok {
		return key, nil
	}
	return nil, nil
}

func loadCertificate(b []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(b)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
