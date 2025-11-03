package sbc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"

	"github.com/q0jt/line-sbc/sbc/internal/argon2"
)

func randomBytes(size int) []byte {
	rng := make([]byte, size)
	rand.Read(rng)
	return rng
}

func deriveKey(key, salt []byte, info string, size int) ([]byte, error) {
	return hkdf.Key(sha256.New, key, salt, info, size)
}

func hashPasswordArgon2id(passwd []byte, mid, ad string) ([]byte, error) {
	return argon2.IDKeyWithAssociatedData(
		passwd, []byte(mid), []byte(ad), 4, 128*1024, 4, 0x10)
}

func generateShardSecret(pk *ecdh.PublicKey) ([]byte, []byte, error) {
	curve := ecdh.P256()
	esk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	secret, err := esk.ECDH(pk)
	if err != nil {
		return nil, nil, err
	}
	epk := stripP256PubKeyPrefix(esk.PublicKey().Bytes())
	return epk, secret, nil
}

func stripP256PubKeyPrefix(key []byte) []byte {
	if len(key) != 65 && key[0] != 0x04 {
		return key
	}
	return key[1:]
}

func aesCTRCrypto(key, iv, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(src))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(dst, src)
	return dst, nil
}

func aeadEncrypt(key, nonce, src, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, src, aad), nil
}

func aeadDecrypt(key, nonce, src, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, nonce, src, aad)
}
