package sbc

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"github.com/q0jt/line-sbc/sbc/internal/argon2"
)

func randomBytes(size int) []byte {
	dst := make([]byte, size)
	rand.Read(dst)
	return dst
}

func deriveKey(key, salt []byte, info string, size int) ([]byte, error) {
	return hkdf.Key(sha256.New, key, salt, info, size)
}

func hashPasswordArgon2id(passwd []byte, mid, ad string) ([]byte, error) {
	return argon2.IDKeyWithAssociatedData(
		passwd, []byte(mid), []byte(ad), 4, 128*1024, 4, 0x10)
}

func generateShardSecret(publicKey *ecdh.PublicKey) ([]byte, []byte, error) {
	curve := ecdh.P256()
	esk, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	secret, err := esk.ECDH(publicKey)
	if err != nil {
		return nil, nil, err
	}
	epk, err := stripP256PubKeyPrefix(esk.PublicKey())
	if err != nil {
		return nil, nil, err
	}
	return epk, secret, nil
}

func stripP256PubKeyPrefix(publicKey *ecdh.PublicKey) ([]byte, error) {
	if publicKey.Curve() != ecdh.P256() {
		return nil, errors.New("sbc: invalid curve interface")
	}
	pb := publicKey.Bytes()
	if len(pb) != 65 && pb[0] != 0x04 {
		return nil, errors.New("sbc: invalid public key")
	}
	return pb[1:], nil
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
