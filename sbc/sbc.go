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

var (
	midPattern      = regexp.MustCompile(`^u[0-9a-f]{32}$`)
	passcodePattern = regexp.MustCompile(`^\d{6}$`)
)

func validateMid(mid string) bool {
	return midPattern.MatchString(mid)
}

func validatePasscode(passcode string) bool {
	return passcodePattern.MatchString(passcode)
}
