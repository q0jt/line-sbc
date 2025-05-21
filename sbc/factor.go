package sbc

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"os"
	"time"
)

type factorType uint32

const (
	factorTypePassword factorType = iota + 1
	factorTypeRecoveryCode
)

type SecretFactor struct {
	mid        string
	credential string
	factorType factorType
}

type RestoreClaimV3 struct {
	mid   string
	seed  []byte
	claim []byte
}

func (f *SecretFactor) RestoreClaim(path string) (*RestoreClaimV3, error) {
	timestamp := time.Now().UnixMilli()
	return createFromSecretFactor(f, timestamp, path, true)
}

func CreateFromPassword(mid, password string) (*SecretFactor, error) {
	return newSecretFactor(mid, password, factorTypePassword)
}

//func CreateFromRecoveryCode(mid, code string) (*SecretFactor, error) {
//	return newSecretFactor(mid, code, factorTypeRecoveryCode)
//}

func newSecretFactor(mid, credential string, factorType factorType) (*SecretFactor, error) {
	if factorType != factorTypePassword && factorType != factorTypeRecoveryCode {
		return nil, errors.New("sbc: unsupported factor type")
	}
	factor := SecretFactor{
		mid:        mid,
		factorType: factorType,
		credential: credential,
	}
	return &factor, nil
}

func (f *SecretFactor) hashCredential() []byte {
	info := "V2_ARGON2_PASSWORD"
	if f.factorType != factorTypePassword {
		info = "V2_ARGON2_RECOVERY"
	}
	return hashPasswordArgon2id([]byte(f.credential), f.mid, info)
}

func createFromSecretFactor(factor *SecretFactor, timestamp int64, path string, rel bool) (*RestoreClaimV3, error) {
	if !validateMid(factor.mid) {
		return nil, ErrInvalidMid
	}
	cert, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := importServicePubKeys(cert, caTypeNitrokey, rel)
	if err != nil {
		return nil, err
	}
	return makeRestoreClaimV3(factor, timestamp, key)
}

func makeRestoreClaimV3(factor *SecretFactor, timestamp int64, pk *ecdh.PublicKey) (*RestoreClaimV3, error) {
	rng := randomBytes(0x10)

	envelope, err := wrapBackupECDHKey(pk, rng, "V2_CLAIM_SHARED")
	if err != nil {
		return nil, err
	}

	seed, err := deriveKey(rng, []byte(factor.mid), "V2_CLAIM_SEED", 0x1c)
	if err != nil {
		return nil, err
	}

	// aad (0x6d bytes): version? 2 bytes || mid 0x21 bytes || timestamp 8 bytes || ephemeralKey 0x40 bytes || factorType 2 bytes
	aad := make([]byte, 0, 0x6d)
	aad = binary.LittleEndian.AppendUint16(aad, uint16(3))
	aad = append(aad, []byte(factor.mid)...)
	aad = binary.LittleEndian.AppendUint64(aad, uint64(timestamp))
	aad = append(aad, envelope.tempKey...)
	aad = binary.LittleEndian.AppendUint16(aad, uint16(factor.factorType))

	h := factor.hashCredential()

	ciphertext, err := aeadEncrypt(seed[:0x10], seed[0x10:], h, aad)
	if err != nil {
		return nil, err
	}
	claim, err := marshalClaimV3([]byte(factor.mid), ciphertext, envelope, timestamp)
	if err != nil {
		return nil, err
	}
	return newRestoreClaimV3(factor.mid, claim, rng), nil
}

func newRestoreClaimV3(mid string, claim, seed []byte) *RestoreClaimV3 {
	return &RestoreClaimV3{mid: mid, claim: claim, seed: seed}
}

func (v *RestoreClaimV3) Seed() []byte {
	return v.seed
}

func (v *RestoreClaimV3) Claim() []byte {
	return v.claim
}

func (v *RestoreClaimV3) Restore() {
}
