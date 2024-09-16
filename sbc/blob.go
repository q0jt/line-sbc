package sbc

import (
	"encoding/json"

	"github.com/q0jt/line-sbc/sbc/internal/msgpack"
)

type BackupKey struct {
	CreatedTime    int64  `json:"created_time"`
	Version        int32  `json:"version"`
	E2eePrivateKey string `json:"encoded_private_key"`
	E2eePublicKey  string `json:"encoded_public_key"`
}

type LetterSealingKey struct {
	KeyID     int32
	BackupKey *BackupKey
}

type LetterSealingKeys []*LetterSealingKey

func makeRestoreBackupKeys(seed, ek, payload []byte) (LetterSealingKeys, error) {
	key, err := hkdf(seed, nil, []byte("RESTORE_SEED"), 0x10, 0x10)
	if err != nil {
		return nil, err
	}
	rk, err := msgpack.UnpackRecoveryKey(ek)
	if err != nil {
		return nil, err
	}
	out, err := cryptoAesCTR(key[:0x10], key[0x10:], rk)
	if err != nil {
		return nil, err
	}
	bs, err := hkdf(out, nil, []byte("BACKUP_SEED"), 0x10, 0xc)
	if err != nil {
		return nil, err
	}
	blob, err := msgpack.UnpackBlobPayload(payload)
	if err != nil {
		return nil, err
	}
	aad, err := msgpack.EncodeBlobPayloadMetaData(blob)
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptAesGCM(bs[:0x10], bs[0x10:], blob.Payload, aad)
	if err != nil {
		return nil, err
	}
	section, err := msgpack.UnpackEncryptSection(plaintext)
	if err != nil {
		return nil, err
	}

	size := len(section)
	keys := make(LetterSealingKeys, 0, size)

	for i := 0; i < size; i++ {
		var bk BackupKey
		if err := json.Unmarshal(section[i], &bk); err != nil {
			return nil, err
		}
		keys = append(keys, &LetterSealingKey{
			KeyID:     blob.MetaData[i],
			BackupKey: &bk})
	}

	return keys, nil
}
