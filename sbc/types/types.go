package types

type KeyType int

const (
	KeyTypeLetterSealing KeyType = iota + 1
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
