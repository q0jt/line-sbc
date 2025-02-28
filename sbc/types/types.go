package types

type BackupKeyType int

const (
	KeyTypeE2eeKey BackupKeyType = iota + 1
	KeyTypeBackupPin
	KeyTypeBackupMasterKey
)

type FactorType int

const (
	FactorTypePassword FactorType = iota
	FactorTypeRecoveryCode
)

type PayloadType int

const (
	PayloadTypeLetterSealingKey PayloadType = iota
	PayloadTypeInitialFullSyncKey
)
