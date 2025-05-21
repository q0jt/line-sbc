package sbc

import (
	"encoding/json"
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
	decryptedKey, err := decryptRecoveryKey(seed, key)
	if err != nil {
		return nil, err
	}
	bs, err := deriveKey(decryptedKey, nil, "BACKUP_SEED", 0x1c)
	if err != nil {
		return nil, err
	}
	blob, err := unmarshalBlobPayload(payload)
	if err != nil {
		return nil, err
	}
	aad, err := marshalBlobPayloadMetaData(blob)
	if err != nil {
		return nil, err
	}
	plaintext, err := aeadDecrypt(bs[:0x10], bs[0x10:], blob.EncryptedSection, aad)
	if err != nil {
		return nil, err
	}
	slots, err := unmarshalBackupKeySlots(plaintext, blob.isMigration)
	if err != nil {
		return nil, err
	}
	return generateBackupKeys(slots.e2eeKeys, blob.MetaData, slots.pin)
}

func decryptRecoveryKey(seed, key []byte) ([]byte, error) {
	rs, err := deriveKey(seed, nil, "RESTORE_SEED", 0x20)
	if err != nil {
		return nil, err
	}
	recoveryKey, err := unmarshalRecoveryKey(key)
	if err != nil {
		return nil, err
	}
	return aesCTRCrypto(rs[:0x10], rs[0x10:], recoveryKey)
}

func generateBackupKeys(slot [][]byte, ids []int32, pin string) (*BackupKeys, error) {
	size := len(slot)
	keys := make(E2eeKeys, 0, size)

	for i := 0; i < size; i++ {
		var data E2eeKeyData
		if err := json.Unmarshal(slot[i], &data); err != nil {
			return nil, err
		}
		keys = append(keys, &E2eeKey{
			KeyID:   ids[i],
			E2eeKey: &data,
		})
	}

	backupKeys := BackupKeys{
		E2eeKeys: keys,
		Passcode: pin,
	}

	return &backupKeys, nil
}
