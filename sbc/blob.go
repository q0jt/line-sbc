package sbc

import (
	"encoding/json"
	"errors"
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
	E2eeKeys  E2eeKeys
	Passcode  string
	MasterKey []byte
}

func (k *BackupKeys) HasPasscode() bool {
	return len(k.Passcode) != 0
}

func (k *BackupKeys) HasMasterKey() bool {
	return len(k.MasterKey) != 0
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
	plaintext, err := aeadDecrypt(bs[:0x10], bs[0x10:], blob.encryptedData, aad)
	if err != nil {
		return nil, err
	}
	slots, err := unmarshalBackupKeySlots(plaintext, blob.meta)
	if err != nil {
		return nil, err
	}
	return generateBackupKeys(slots, blob.e2eeKeyIds)
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

func generateBackupKeys(slots *keySlots, ids []int32) (*BackupKeys, error) {
	keySize := len(slots.e2eeKeys)
	if len(ids) != keySize {
		return nil, errors.New("sbc: key id count does not match key size")
	}

	keys := make(E2eeKeys, 0, keySize)

	for i := range keySize {
		var data E2eeKeyData
		if err := json.Unmarshal(slots.e2eeKeys[i], &data); err != nil {
			return nil, err
		}
		keys = append(keys, &E2eeKey{
			KeyID:   ids[i],
			E2eeKey: &data,
		})
	}

	backupKeys := BackupKeys{
		E2eeKeys:  keys,
		Passcode:  slots.pin,
		MasterKey: slots.masterKey,
	}

	return &backupKeys, nil
}
