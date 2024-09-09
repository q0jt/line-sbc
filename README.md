# line-sbc

# Spec
### RestoreClaim 

```json
[
  2, // keyType: Backup PIN
  0000000000000, // getServerTime()
  "temporary ECDSA-P256 public key",
  [
    [
      "backup certificate ECDSA-P256 public key", // getE2EEKeyBackupCertificates()
      "encrypted seed"
    ]
  ],
  "encrypted pin"
]
```

- **field1**: uint, typeId(2), PIN
- **field2**: uint, request time(getServerTime)
- **field3**: bin, generate ECDSA-P256 public key
- **field4**: bin, backup certificate ECDSA-P256 public key
- **field5**: bin, encrypted seed
- **field6**: bin, encrypted pin

### Recovery Key

```json
[
  1,
  "encrypted key"
]
```

- **field1**: uint, objectType(1), LetterSealing Key
- **field2**: bin, encrypted key

### Blob Header

```json
[
  2, // keyType: Backup PIN
  0000000000000, // getServerTime()
  "temporary ECDSA-P256 public key",
  [
    [
      "backup certificate ECDSA-P256 public key", // getE2EEKeyBackupCertificates()
      "encrypted seed"
    ]
  ],
  "encrypted pin"
]
```
- **field1**: uint, typeId(2), PIN
- **field2**: uint, request time(getServerTime)
- **field3**: bin, generate ECDSA-P256 public key
- **field4**: bin, backup certificate ECDSA-P256 public key
- **field5**: bin, encrypted seed
- **field6**: bin, encrypted pin

field5: 32 bytes

### BlobPayload

### Get Backup Cert

```
cert = getE2EEKeyBackupCertificates()
GET https://obs.line-scdn.net/{cert}
```
