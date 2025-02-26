### How To Generate
```shell
mkdir service # any directory
thrift --out service --gen go:skip_remote backup.thrift
```

### Services
- E2EEKeyBackupService(`/EKBS4`)
  - createE2EEKeyBackupEnforced
  - deleteE2EEKeyBackup
  - restoreE2EEKeyBackup
  - getE2EEKeyBackupInfo
  - getE2EEKeyBackupCertificates


- E2eeKeyBackupCertificateService(`/KBCS`)
  - getKeyBackupCertificatesV2


- E2EELifetimeKeyBackupService(`/LKBS4`)
  - createLifetimeKeyBackup
  - restoreLifetimeKeyBackupHeader
  - validateLifetimeKeyBackupHeader
  - addLifetimeKeyBackupPayloadDataList
  - getLifetimeKeyBackupPayloadDataList

> [!NOTE]
> 
> Based on Line iOS version 15 and Android version 15
