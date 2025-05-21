package sbc

import (
	"encoding/binary"
)

type PayloadContent struct {
	Type PayloadType
	Key  []byte
}

func decryptBackupPayload(seed, mid, key, payload []byte) (*PayloadContent, error) {
	masterKey, err := decryptRecoveryKeyV2(seed, mid, key)
	if err != nil {
		return nil, err
	}
	bp, err := unmarshalBackupPayload(payload)
	if err != nil {
		return nil, err
	}
	master, err := deriveKey(masterKey, bp.challenge, "V2_PAYLOAD_MASTER", 0x1C)
	if err != nil {
		return nil, err
	}
	aad := make([]byte, 0, 4+len(bp.metaData)*8)
	aad = binary.LittleEndian.AppendUint16(aad, uint16(2))
	aad = binary.LittleEndian.AppendUint16(aad, uint16(bp.payloadType))
	for _, t := range bp.metaData {
		aad = binary.LittleEndian.AppendUint64(aad, t)
	}
	content, err := aeadDecrypt(master[:0x10], master[0x10:], bp.data, aad)
	if err != nil {
		return nil, err
	}
	return &PayloadContent{Type: PayloadType(bp.payloadType), Key: content}, nil
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
	aad := make([]byte, 0, 0xa)
	aad = binary.LittleEndian.AppendUint16(aad, uint16(2)) // version
	aad = binary.LittleEndian.AppendUint64(aad, recoveryKey.timestamp)
	return aeadDecrypt(rs[:0x10], rs[0x10:], recoveryKey.encryptedKey, aad)
}
