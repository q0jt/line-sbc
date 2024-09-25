package sbc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"

	"github.com/q0jt/crypto/argon2"
	kdf "github.com/q0jt/crypto/hkdf"
)

func sha256Sum(b []byte) []byte {
	sum := sha256.Sum256(b)
	return sum[:]
}

func randomBytes(size int) ([]byte, error) {
	rng := make([]byte, size)
	if _, err := rand.Read(rng); err != nil {
		return nil, err
	}
	return rng, nil
}

func hkdf(key, salt, info []byte, size, iv uint32) ([]byte, error) {
	h := kdf.New(sha256.New, key, salt, info)
	out := make([]byte, size+iv)
	if _, err := h.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func argon2id(pwd, mid, aad []byte) []byte {
	return argon2.IDKeyWithAAD(
		pwd, mid, aad, 4, 128*1024, 4, 0x10)
}

func genShardSecret(pk *ecdh.PublicKey) (*ecdh.PrivateKey, []byte, error) {
	curve := ecdh.P256()
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	secret, err := key.ECDH(pk)
	if err != nil {
		return nil, nil, err
	}
	return key, secret, nil
}

func stripP256Prefix(key []byte) []byte {
	if len(key) != 65 && key[0] != 0x04 {
		return key
	}
	return key[1:]
}

func cryptoAesCTR(key, iv, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(src))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ciphertext, src)
	return ciphertext, nil
}

func encryptAesGCM(key, nonce, src, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, src, aad), nil
}

func decryptAesGCM(key, nonce, src, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, src, aad)
}
