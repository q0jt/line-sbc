package sbc

import (
	"errors"
)

type FactorType int

const (
	FactorTypePassword FactorType = iota
	FactorTypeRecoveryCode
)

type SecretFactor struct {
	mid        string
	factorType FactorType
}

func NewSecretFactor(factorType FactorType, cred, mid string) ([]byte, error) {
	if !validateMid(mid) {
		return nil, errors.New("sbc: invalid mid")
	}
	factor, err := newSecretFactorFromType(factorType)
	if err != nil {
		return nil, err
	}
	factor.mid = mid
	return factor.generateCredential(cred), nil
}

func newSecretFactorFromType(factorType FactorType) (*SecretFactor, error) {
	if factorType != FactorTypePassword && factorType != FactorTypeRecoveryCode {
		return nil, errors.New("sbc: unsupported factor type")
	}
	return &SecretFactor{factorType: factorType}, nil
}

func (f *SecretFactor) generateCredential(cred string) []byte {
	info := "V2_ARGON2_RECOVERY"
	if f.factorType == FactorTypePassword {
		info = "V2_ARGON2_PASSWORD"
	}
	return hashPasswordArgon2id([]byte(cred), f.mid, info)
}
