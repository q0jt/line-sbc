package sbc

import (
	"errors"

	"github.com/q0jt/line-sbc/sbc/types"
)

type SecretFactor struct {
	factorType types.FactorType
}

func NewSecretFactor(factorType types.FactorType, cred, mid string) ([]byte, error) {
	if !validateMid(mid) {
		return nil, errors.New("sbc: invalid mid")
	}
	factor, err := newSecretFactorFromFactorType(factorType)
	if err != nil {
		return nil, err
	}
	return factor.generateCredential(cred, mid), nil
}

func newSecretFactorFromFactorType(factorType types.FactorType) (*SecretFactor, error) {
	if factorType != types.FactorTypePassword && factorType != types.FactorTypeRecoveryCode {
		return nil, errors.New("sbc: unsupported factor type")
	}
	return &SecretFactor{factorType: factorType}, nil
}

func (f *SecretFactor) generateCredential(cred, mid string) []byte {
	info := "V2_ARGON2_RECOVERY"
	if f.factorType == types.FactorTypePassword {
		info = "V2_ARGON2_PASSWORD"
	}
	return argon2id([]byte(cred), []byte(mid), info)
}
