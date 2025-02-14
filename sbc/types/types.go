package types

type KeyType int

const (
	KeyTypeLetterSealing KeyType = iota + 1
	KeyTypeBackupPin
	KeyTypeBackupMasterKey
)
