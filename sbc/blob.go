package sbc

import (
	"encoding/json"

	"github.com/q0jt/line-sbc/sbc/internal/msgpack"
)

type E2eeKey struct {
	CreatedTime    int64  `json:"created_time"`
	Version        int32  `json:"version"`
	E2eePrivateKey string `json:"encoded_private_key"`
	E2eePublicKey  string `json:"encoded_public_key"`
}

type LetterSealingKey struct {
	KeyID   int32
	E2eeKey *E2eeKey
}

type LetterSealingKeys []*LetterSealingKey

type BackupKeys struct {
	LetterSealingKeys LetterSealingKeys
	Passcode          string
}

func makeRestoreBackupKeys(seed, ek, payload []byte) (*BackupKeys, error) {
	key, err := deriveKey(seed, nil, "RESTORE_SEED", 0x20)
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
	bs, err := deriveKey(out, nil, "BACKUP_SEED", 0x1c)
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
	section, pin, err := msgpack.UnpackEncryptSection(plaintext, blob.ContainsPin())
	if err != nil {
		return nil, err
	}

	size := len(section)
	keys := make(LetterSealingKeys, 0, size)

	for i := 0; i < size; i++ {
		var ee E2eeKey
		if err := json.Unmarshal(section[i], &ee); err != nil {
			return nil, err
		}
		keys = append(keys, &LetterSealingKey{
			KeyID:   blob.MetaData[i],
			E2eeKey: &ee,
		})
	}

	var backupKeys BackupKeys

	backupKeys.LetterSealingKeys = keys

	if blob.ContainsPin() {
		backupKeys.Passcode = pin
	}

	return &backupKeys, nil
}
