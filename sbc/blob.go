package sbc

import (
	"encoding/json"

	"github.com/q0jt/line-sbc/sbc/internal/msgpack"
)

type E2eeKeyData struct {
	CreatedTime int64  `json:"created_time"`
	Version     int32  `json:"version"`
	PrivateKey  string `json:"encoded_private_key"`
	PublicKey   string `json:"encoded_public_key"`
}

type E2eeKey struct {
	KeyID   int32
	E2eeKey *E2eeKeyData
}

type E2eeKeys []*E2eeKey

type BackupKeys struct {
	E2eeKeys E2eeKeys
	Passcode string
}

func makeRestoreBackupKeys(seed, key, payload []byte) (*BackupKeys, error) {
	rs, err := deriveKey(seed, nil, "RESTORE_SEED", 0x20)
	if err != nil {
		return nil, err
	}
	rk, err := msgpack.UnpackRecoveryKey(key)
	if err != nil {
		return nil, err
	}
	out, err := aesCTRCrypto(rs[:0x10], rs[0x10:], rk)
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
	aad, err := marshalBlobPayloadMetaData(blob)
	if err != nil {
		return nil, err
	}
	plaintext, err := aeadDecrypt(bs[:0x10], bs[0x10:], blob.Payload, aad)
	if err != nil {
		return nil, err
	}
	section, pin, err := msgpack.UnpackEncryptSection(plaintext, blob.ContainsPin())
	if err != nil {
		return nil, err
	}

	size := len(section)
	keys := make(E2eeKeys, 0, size)

	for i := 0; i < size; i++ {
		var data E2eeKeyData
		if err := json.Unmarshal(section[i], &data); err != nil {
			return nil, err
		}
		keys = append(keys, &E2eeKey{
			KeyID:   blob.MetaData[i],
			E2eeKey: &data,
		})
	}

	var backupKeys BackupKeys

	backupKeys.E2eeKeys = keys

	if blob.ContainsPin() {
		backupKeys.Passcode = pin
	}

	return &backupKeys, nil
}
