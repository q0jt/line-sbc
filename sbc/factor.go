package sbc

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"os"
	"time"
)

const masterKeySize = 0x10

type factorType uint32

const (
	factorTypePassword factorType = iota + 1
	factorTypeRecoveryCode
)

type SecretFactor struct {
	mid        string
	cred       string
	factorType factorType
}

type RestoreClaimV3 struct {
	mid   string
	seed  []byte
	claim []byte
}

func (f *SecretFactor) RestoreClaim(path string) (*RestoreClaimV3, error) {
	timestamp := uint64(time.Now().UnixMilli())
	return createFromSecretFactor(f, timestamp, path, true)
}

func CreateClaimV3FromSeed(mid string, seed []byte) *RestoreClaimV3 {
	return newRestoreClaimV3(mid, nil, seed)
}

func CreateFromPassword(mid, password, path string) (*RestoreClaimV3, error) {
	factor, err := newSecretFactor(mid, password, factorTypePassword)
	if err != nil {
		return nil, err
	}
	return factor.RestoreClaim(path)
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
		cred:       credential,
	}
	return &factor, nil
}

func (f *SecretFactor) hashCredential() []byte {
	info := "V2_ARGON2_PASSWORD"
	if f.factorType != factorTypePassword {
		info = "V2_ARGON2_RECOVERY"
	}
	return hashPasswordArgon2id([]byte(f.cred), f.mid, info)
}

func createFromSecretFactor(factor *SecretFactor, timestamp uint64, path string, rel bool) (*RestoreClaimV3, error) {
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

func makeRestoreClaimV3(factor *SecretFactor, timestamp uint64, pk *ecdh.PublicKey) (*RestoreClaimV3, error) {
	seed := randomBytes(0x10)

	envelope, err := wrapBackupECDHKey(pk, seed, "V2_CLAIM_SHARED")
	if err != nil {
		return nil, err
	}

	cek, err := deriveKey(seed, []byte(factor.mid), "V2_CLAIM_SEED", 0x1c)
	if err != nil {
		return nil, err
	}

	// aad (0x6d bytes): claim version? 2 bytes || mid 0x21 bytes ||
	// timestamp 8 bytes || ephemeralKey 0x40 bytes || factorType 2 bytes
	aad := make([]byte, 0, 0x6d)
	aad = binary.LittleEndian.AppendUint16(aad, uint16(3))
	aad = append(aad, []byte(factor.mid)...)
	aad = binary.LittleEndian.AppendUint64(aad, timestamp)
	aad = append(aad, envelope.tempKey...)
	aad = binary.LittleEndian.AppendUint16(aad, uint16(factor.factorType))

	h := factor.hashCredential()

	ciphertext, err := aeadEncrypt(cek[:0x10], cek[0x10:], h, aad)
	if err != nil {
		return nil, err
	}
	claim, err := marshalClaimV3(envelope, []byte(factor.mid), ciphertext, uint8(factor.factorType), timestamp)
	if err != nil {
		return nil, err
	}
	return newRestoreClaimV3(factor.mid, claim, seed), nil
}

func newRestoreClaimV3(mid string, claim, seed []byte) *RestoreClaimV3 {
	return &RestoreClaimV3{mid: mid, claim: claim, seed: seed}
}

func (v *RestoreClaimV3) Restore(key, payload []byte) (*PayloadSecret, error) {
	if len(key) == 0 {
		return nil, errors.New("sbc: invalid key size")
	}
	if len(payload) == 0 {
		return nil, errors.New("sbc: invalid payload size")
	}
	if len(key) != masterKeySize {
		if len(v.seed) != 0 {
			return decryptPayloadSecretFromRecoveryKey(v.seed, []byte(v.mid), key, payload)
		}
		return nil, errors.New("sbc: invalid seed size")
	}
	return decryptPayloadSecret(key, payload)
}

func (v *RestoreClaimV3) Seed() []byte {
	return v.seed
}

func (v *RestoreClaimV3) Claim() []byte {
	return v.claim
}
