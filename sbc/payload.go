package sbc

import (
	"encoding/binary"
)

type PayloadType uint

const (
	PayloadTypeE2eeKey PayloadType = iota + 1
	PayloadTypeInitialFullSyncKey
)

type PayloadSecret struct {
	Type PayloadType
	Key  []byte
}

func decryptPayloadSecretFromRecoveryKey(seed, mid, key, payload []byte) (*PayloadSecret, error) {
	masterKey, err := decryptRecoveryKeyV2(seed, mid, key)
	if err != nil {
		return nil, err
	}
	return decryptPayloadSecret(masterKey, payload)
}

func decryptPayloadSecret(masterKey, payload []byte) (*PayloadSecret, error) {
	bp, err := unmarshalBackupPayload(payload)
	if err != nil {
		return nil, err
	}
	master, err := deriveKey(masterKey, bp.nonce, "V2_PAYLOAD_MASTER", 0x1C)
	if err != nil {
		return nil, err
	}
	// aad: version 2 bytes || payload type 2 bytes || timestamp1 8 bytes ||
	// timestamp2 8 bytes || e2ee public key 32 bytes(when PayloadTypeE2eeKey)
	aadSize := 4 + len(bp.metaData)*8 + len(bp.publicKey)
	aad := make([]byte, 0, aadSize)
	aad = binary.LittleEndian.AppendUint16(aad, uint16(2))
	aad = binary.LittleEndian.AppendUint16(aad, uint16(bp.payloadType))
	for _, t := range bp.metaData {
		aad = binary.LittleEndian.AppendUint64(aad, t)
	}
	if bp.payloadType != PayloadTypeInitialFullSyncKey {
		aad = append(aad, bp.publicKey...)
	}
	content, err := aeadDecrypt(master[:0x10], master[0x10:], bp.data, aad)
	if err != nil {
		return nil, err
	}
	return &PayloadSecret{Type: bp.payloadType, Key: content}, nil
}

func decryptRecoveryKeyV2(seed, mid, key []byte) ([]byte, error) {
	rs, err := deriveKey(seed, mid, "V2_RESTORE_SEED", 0x1C)
	if err != nil {
		return nil, err
	}
	recoveryKey, err := unmarshalRecoveryKeyV2(key)
	if err != nil {
		return nil, err
	}
	// aad: key version 2bytes || timestamp 8 bytes
	aad := make([]byte, 0, 0xa)
	aad = binary.LittleEndian.AppendUint16(aad, uint16(2))
	aad = binary.LittleEndian.AppendUint64(aad, recoveryKey.timestamp)
	return aeadDecrypt(rs[:0x10], rs[0x10:], recoveryKey.encryptedKey, aad)
}
