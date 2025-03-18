# line-sbc
LINE-SBC is an implementation based on the reverse engineering of the Secure Backup Client.     
It consists of client-side encryption (CSE) and the OPAQUE protocol base.   
go1.24.0 or later is required

[![Go Reference](https://pkg.go.dev/badge/github.com/q0jt/line-sbc.svg)](https://pkg.go.dev/github.com/q0jt/line-sbc)

### Usage
```
go get -u github.com/q0jt/line-sbc
```

### How To Get Backup Cert
```
E2EEKeyBackupService

// Intel SGX(Software Guard Extensions) base
certificateId = getE2EEKeyBackupCertificates()
GET https://obs.line-scdn.net/{certificateId}

E2eeKeyBackupCertificateService

// Hardware Security Module(HSM) base
certificateId = getKeyBackupCertificatesV2()
GET https://obs.line-scdn.net/{certificateId}
```

### Getting started
1. Decrypt backup keys from backup PIN
```go
// CreateFromPin("uxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "123456", "server-LNSGXTE1505.backup.security.linecorp.com.pem")
claim, err := sbc.CreateFromPin("mid", "backup PIN", "cert path")
if err != nil {
	// error
}
restore, err := RestoreE2EEKeyBackup(
	&RestoreE2EEKeyBackupRequest{
		RestoreClaim: claim.Claim(),
	})
keys, err := claim.Restore(restore.RecoveryKey, restore.BlobPayload)
if err != nil {
	// error
}
// Only when migrated to another device and when PIN is registered
fmt.Println("pin: ", keys.Passcode)
for _, key := range keys.LetterSealingKeys {
    fmt.Printf("key id: %d\n", key.KeyID)
    fmt.Printf("private key: %s\n", key.E2eeKey.PrivateKey)
}
```

2. Decrypt backup keys from seed
```go
claim := sbc.CreateClaimFromSharedSecret(seed)
keys, err := claim.Restore(key, payload)
if err != nil {
    // error
}
```

> [!NOTE]
>
> ```
> E2EEKeyBackupException({Code:INVALID_PIN Reason:invalid pin ParameterMap:map[failedAttemptCount:2 maxAttemptCount:10]})
> ```
> There is an anti-brute force mechanism, and after 10 attempts at the backup PIN, the server will permanently lock the data containing the E2EE key, making it inaccessible.
