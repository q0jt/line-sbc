package sbc

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"time"
)

type RestoreClaim struct {
	claim []byte
	seed  []byte
}

func CreateClaimFromSharedSecret(secret []byte) *RestoreClaim {
	return newRestoreClaim(nil, secret)
}

func newRestoreClaim(claim, seed []byte) *RestoreClaim {
	return &RestoreClaim{claim: claim, seed: seed}
}

// CreateFromPin generates a claim using the user's internal identifier,
// a 6-digit passcode, and a service certificate.
func CreateFromPin(mid, passcode, path string) (*RestoreClaim, error) {
	timestamp := uint64(time.Now().UnixMilli())
	return CreateFromPinWithServerTime(mid, passcode, path, timestamp)
}

func CreateFromPinWithServerTime(mid, passcode, path string, timestamp uint64) (*RestoreClaim, error) {
	return createFromPin(mid, passcode, path, timestamp, true)
}

func createFromPin(mid, passcode, path string, timestamp uint64, rel bool) (*RestoreClaim, error) {
	if !validateMid(mid) {
		return nil, ErrInvalidMid
	}
	if !validatePasscode(passcode) {
		return nil, ErrInvalidPasscode
	}
	key, err := loadServiceCertificate(path, caTypeSGX, rel)
	if err != nil {
		return nil, err
	}
	return makeRestoreClaim(mid, passcode, timestamp, key)
}

func makeRestoreClaim(mid, passcode string, timestamp uint64, pk *ecdh.PublicKey) (*RestoreClaim, error) {
	seed := randomBytes(0x10)

	envelope, err := wrapBackupECDHKey(pk, seed, "CLAIM_SHARED")
	if err != nil {
		return nil, err
	}

	pek, err := deriveKey(seed, []byte(mid), "CLAIM_SEED", 0x1c)
	if err != nil {
		return nil, err
	}

	h := hashPasswordArgon2id([]byte(passcode), mid, "ARGON2_PIN")

	aad := make([]byte, 0, 8)
	aad = binary.BigEndian.AppendUint64(aad, timestamp)

	enc, err := aeadEncrypt(pek[:0x10], pek[0x10:], h, aad)
	if err != nil {
		return nil, err
	}

	claim, err := marshalClaim(envelope, enc, timestamp)
	if err != nil {
		return nil, err
	}

	return newRestoreClaim(claim, seed), nil
}

type keyEnvelope struct {
	wrapKey []byte
	tempKey []byte
}

func wrapBackupECDHKey(pk *ecdh.PublicKey, seed []byte, info string) (*keyEnvelope, error) {
	key, secret, err := generateShardSecret(pk)
	if err != nil {
		return nil, err
	}
	cs, err := deriveKey(secret, nil, info, 0x20)
	if err != nil {
		return nil, err
	}
	ciphertext, err := aesCTRCrypto(cs[:0x10], cs[0x10:], seed)
	if err != nil {
		return nil, err
	}

	serverKey := stripP256PubKeyPrefix(pk.Bytes())

	wrapKey, err := marshalKeyWrap(serverKey, ciphertext)
	if err != nil {
		return nil, err
	}

	return &keyEnvelope{wrapKey: wrapKey, tempKey: key}, nil
}

func (c *RestoreClaim) Restore(key, payload []byte) (*BackupKeys, error) {
	if len(c.seed) == 0 {
		return nil, errors.New("sbc: invalid seed size")
	}
	if len(key) == 0 {
		return nil, errors.New("sbc: invalid key size")
	}
	if len(payload) == 0 {
		return nil, errors.New("sbc: invalid payload size")
	}
	return makeRestoreBackupKeys(c.seed, key, payload)
}

func (c *RestoreClaim) Seed() []byte { return c.seed }

func (c *RestoreClaim) Claim() []byte { return c.claim }
