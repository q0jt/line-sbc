package sbc

type BackupKeyType int

const (
	BackupKeyTypeE2eeKey BackupKeyType = iota + 1
	BackupKeyTypeBackupPin
	BackupKeyTypeBackupMasterKey
)

type PayloadType int

const (
	PayloadTypeE2eeKey PayloadType = iota
	PayloadTypeInitialFullSyncKey
)
