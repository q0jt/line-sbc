package sbc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"

	"github.com/q0jt/crypto/argon2"
)

func randomBytes(size int) ([]byte, error) {
	rng := make([]byte, size)
	rand.Read(rng)
	return rng, nil
}

func deriveKey(key, salt []byte, info string, size int) ([]byte, error) {
	return hkdf.Key(sha256.New, key, salt, info, size)
}

func argon2id(pwd, mid []byte, aad string) []byte {
	return argon2.IDKeyWithAAD(
		pwd, mid, []byte(aad), 4, 128*1024, 4, 0x10)
}

func generateEphemeralKey() (*ecdh.PrivateKey, error) {
	curve := ecdh.P256()
	return curve.GenerateKey(rand.Reader)
}

func generateShardSecret(pk *ecdh.PublicKey) ([]byte, []byte, error) {
	sk, err := generateEphemeralKey()
	if err != nil {
		return nil, nil, err
	}
	secret, err := sk.ECDH(pk)
	if err != nil {
		return nil, nil, err
	}
	key := stripP256Prefix(sk.PublicKey().Bytes())
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
