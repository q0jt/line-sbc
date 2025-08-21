### Build
```shell
mkdir /path/to/service
thrift --out /path/to/service --gen go:skip_remote backup.thrift
```

### Services
- E2EEKeyBackupService(`/EKBS4`)
  - createE2EEKeyBackupEnforced
  - deleteE2EEKeyBackup
  - restoreE2EEKeyBackup
  - getE2EEKeyBackupInfo
  - getE2EEKeyBackupCertificates


- E2eeKeyBackupCertificateServer(`/KBCS`)
  - getKeyBackupCertificatesV2


- E2EELifetimeKeyBackupService(`/LKBS4`)
  - createLifetimeKeyBackup
  - restoreLifetimeKeyBackupHeader
  - validateLifetimeKeyBackupHeader
  - addLifetimeKeyBackupPayloadDataList
  - updateLifetimeKeyBackupHeader
  - getLifetimeKeyBackupPayloadDataList
