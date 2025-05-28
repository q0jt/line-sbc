package sbc

import (
	"errors"
	"regexp"
)

var (
	ErrInvalidMid      = errors.New("sbc: invalid mid")
	ErrInvalidPasscode = errors.New("sbc: invalid passcode")
)

type BackupKeyType int

const (
	BackupKeyTypeE2eeKey BackupKeyType = iota + 1
	BackupKeyTypeBackupPin
	BackupKeyTypeBackupMasterKey
)

func validateMid(mid string) bool {
	re := regexp.MustCompile(`u[0-9a-f]{32}`)
	return re.MatchString(mid)
}

func validatePasscode(passcode string) bool {
	re := regexp.MustCompile(`^\d{6}$`)
	return re.MatchString(passcode)
}
