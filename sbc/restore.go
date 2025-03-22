package sbc

import (
	"crypto/ecdh"
	"encoding/binary"
	"errors"
	"os"
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
	timestamp := time.Now().UnixMilli()
	return CreateFromPinWithServerTime(mid, passcode, path, timestamp)
}

func CreateFromPinWithServerTime(mid, passcode, path string, timestamp int64) (*RestoreClaim, error) {
	return createFromPin(mid, passcode, path, timestamp, true)
}

func createFromPin(mid, passcode, path string, timestamp int64, rel bool) (*RestoreClaim, error) {
	if !validateMid(mid) {
		return nil, ErrInvalidMid
	}
	if !validatePasscode(passcode) {
		return nil, ErrInvalidPasscode
	}
	cert, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := importServicePubKeys(cert, caTypeSGX, rel)
	if err != nil {
		return nil, err
	}
	return makeRestoreClaim(mid, passcode, timestamp, key)
}

func makeRestoreClaim(mid, passcode string, timestamp int64, pk *ecdh.PublicKey) (*RestoreClaim, error) {
	rng := randomBytes(0x10)

	warpKey, tempKey, err := wrapBackupECDHKey(pk, rng, "CLAIM_SHARED")
	if err != nil {
		return nil, err
	}

	seed, err := deriveKey(rng, []byte(mid), "CLAIM_SEED", 0x1c)
	if err != nil {
		return nil, err
	}

	hashed := hashPasswordArgon2id([]byte(passcode), mid, "ARGON2_PIN")

	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, uint64(timestamp))

	ciphertext, err := aeadEncrypt(seed[:0x10], seed[0x10:], hashed, aad)
	if err != nil {
		return nil, err
	}

	claim, err := marshalClaim(warpKey, tempKey, ciphertext, timestamp)
	if err != nil {
		return nil, err
	}

	return newRestoreClaim(claim, rng), nil
}

func wrapBackupECDHKey(pk *ecdh.PublicKey, seed []byte, info string) ([]byte, []byte, error) {
	key, secret, err := generateShardSecret(pk)
	if err != nil {
		return nil, nil, err
	}
	cs, err := deriveKey(secret, nil, info, 0x20)
	if err != nil {
		return nil, nil, err
	}
	ciphertext, err := aesCTRCrypto(cs[:0x10], cs[0x10:], seed)
	if err != nil {
		return nil, nil, err
	}

	certKey := stripP256PubKeyPrefix(pk.Bytes())

	wrap, err := marshalKeyWrap(certKey, ciphertext)
	if err != nil {
		return nil, nil, err
	}

	return wrap, key, nil
}

func (c *RestoreClaim) Restore(key, payload []byte) (*BackupKeys, error) {
	if len(c.Seed()) == 0 {
		return nil, errors.New("sbc: invalid seed size")
	}
	if len(key) == 0 {
		return nil, errors.New("sbc: invalid key size")
	}
	if len(payload) == 0 {
		return nil, errors.New("sbc: invalid payload size")
	}
	return makeRestoreBackupKeys(c.Seed(), key, payload)
}

func (c *RestoreClaim) Seed() []byte { return c.seed }

func (c *RestoreClaim) Claim() []byte { return c.claim }
