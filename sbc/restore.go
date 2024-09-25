package sbc

import (
	"crypto/ecdsa"
	"encoding/binary"
	"errors"
	"os"
	"time"

	"github.com/q0jt/line-sbc/sbc/internal/msgpack"
)

type RestoreClaim struct {
	claim []byte
	seed  []byte
}

func CreateClaimFromSharedSecret(secret []byte) *RestoreClaim {
	return newRestoreClaim(nil, secret)
}

// CreateFromPin generates a claim using the user's internal identifier,
// a 6-digit passcode, and a service certificate.
func CreateFromPin(mid, passcode, path string) (*RestoreClaim, error) {
	timestamp := time.Now().UnixMilli()
	return createFromPin(mid, passcode, path, timestamp)
}

func CreateFromPinWithServerTime(mid, passcode, path string, timestamp int64) (*RestoreClaim, error) {
	return createFromPin(mid, passcode, path, timestamp)
}

func newRestoreClaim(claim, seed []byte) *RestoreClaim {
	return &RestoreClaim{claim: claim, seed: seed}
}

func createFromPin(mid, passcode, path string, timestamp int64) (*RestoreClaim, error) {
	if !validateMid(mid) {
		return nil, errors.New("invalid mid")
	}
	if !validatePasscode(passcode) {
		return nil, errors.New("invalid passcode")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := importServiceCert(b, true)
	if err != nil {
		return nil, err
	}
	return makeRestoreClaim(mid, passcode, timestamp, key)
}

func makeRestoreClaim(mid, passcode string, timestamp int64, key *ecdsa.PublicKey) (*RestoreClaim, error) {
	pk, err := key.ECDH()
	if err != nil {
		return nil, err
	}
	sk, sharedSecret, err := genShardSecret(pk)
	if err != nil {
		return nil, err
	}
	cs, err := hkdf(sharedSecret, nil, []byte("CLAIM_SHARED"), 0x10, 0x10)
	if err != nil {
		return nil, err
	}
	rng, err := randomBytes(0x10)
	if err != nil {
		return nil, err
	}
	enc, err := cryptoAesCTR(cs[:0x10], cs[0x10:], rng)
	if err != nil {
		return nil, err
	}
	seed, err := hkdf(rng, []byte(mid), []byte("CLAIM_SEED"), 0x10, 0xc)
	if err != nil {
		return nil, err
	}

	pin := argon2id([]byte(passcode), []byte(mid), []byte("ARGON2_PIN"))

	aad := make([]byte, 8)
	binary.BigEndian.PutUint64(aad, uint64(timestamp))

	ciphertext, err := encryptAesGCM(seed[:0x10], seed[0x10:], pin, aad)
	if err != nil {
		return nil, err
	}

	tempKey := stripP256Prefix(sk.PublicKey().Bytes())
	certKey := stripP256Prefix(pk.Bytes())

	kw := msgpack.NewKeyWrap(certKey, enc)

	claim, err := msgpack.EncodeClaim(kw, tempKey, ciphertext, timestamp)
	if err != nil {
		return nil, err
	}

	return newRestoreClaim(claim, rng), nil
}

func (c *RestoreClaim) Restore(key, payload []byte) (LetterSealingKeys, error) {
	if len(c.Seed()) == 0 {
		return nil, errors.New("invalid seed size")
	}
	if key == nil {
		return nil, errors.New("invalid key size")
	}
	if payload == nil {
		return nil, errors.New("invalid payload size")
	}
	return makeRestoreBackupKeys(c.Seed(), key, payload)
}

func (c *RestoreClaim) Seed() []byte { return c.seed }

func (c *RestoreClaim) Claim() []byte { return c.claim }
