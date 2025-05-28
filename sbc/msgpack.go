package sbc

import (
	"errors"
	"github.com/q0jt/line-sbc/sbc/internal/msgpack"
)

func marshalKeyWrap(key, enc []byte) ([]byte, error) {
	if len(key) != 0x40 {
		return nil, errors.New("sbc/msgpack: invalid public key size")
	}
	if size := len(enc); size != 0x10 && size != 0x20 {
		return nil, errors.New("sbc/msgpack: invalid encrypted seed size")
	}

	encoder := msgpack.NewEncoder()

	encoder.WriteArraySize(2)
	if err := encoder.WriteBinary(key); err != nil {
		return nil, err
	}
	if err := encoder.WriteBinary(enc); err != nil {
		return nil, err
	}

	return encoder.Buffer(), nil
}

func marshalClaim(envelope *keyEnvelope, enc []byte, timestamp uint64) ([]byte, error) {
	encoder := msgpack.NewEncoder()
	encoder.WriteArraySize(5)
	if err := encoder.WriteFixUint(2); err != nil {
		return nil, err
	}
	encoder.WriteUint64(timestamp)
	if err := encoder.WriteBinary(envelope.tempKey); err != nil {
		return nil, err
	}
	encoder.WriteArraySize(1)
	encoder.WriteDirect(envelope.wrapKey)
	if err := encoder.WriteBinary(enc); err != nil {
		return nil, err
	}
	return encoder.Buffer(), nil
}

func marshalClaimV3(envelope *keyEnvelope, mid, enc []byte, ft uint8, timestamp uint64) ([]byte, error) {
	encoder := msgpack.NewEncoder()
	encoder.WriteArraySize(7)
	if err := encoder.WriteFixUint(3); err != nil {
		return nil, err
	}
	if err := encoder.WriteBinary(mid); err != nil {
		return nil, err
	}
	encoder.WriteUint64(timestamp)
	if err := encoder.WriteBinary(envelope.tempKey); err != nil {
		return nil, err
	}
	encoder.WriteArraySize(1)
	encoder.WriteDirect(envelope.wrapKey)
	// factorType
	if err := encoder.WriteFixUint(ft); err != nil {
		return nil, err
	}
	if err := encoder.WriteBinary(enc); err != nil {
		return nil, err
	}
	return encoder.Buffer(), nil
}

func marshalBlobPayloadMetaData(payload *blobPayload) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("sbc/msgpack: no blob payload")
	}

	encoder := msgpack.NewEncoder()

	keyIds := payload.e2eeKeyIds
	size := len(keyIds)

	encoder.WriteArraySize(uint8(size + payload.meta.extra()))

	for _, keyId := range keyIds {
		encoder.WriteArraySize(2)
		if err := encoder.WriteFixUint(1); err != nil {
			return nil, err
		}
		encoder.WriteUint32(uint32(keyId))
	}

	if payload.meta.has(fieldBackupPin) {
		encoder.WriteArraySize(1)
		if err := encoder.WriteFixUint(2); err != nil {
			return nil, err
		}
	}

	if payload.meta.has(fieldMasterKey) {
		encoder.WriteArraySize(2)
		if err := encoder.WriteFixUint(3); err != nil {
			return nil, err
		}
		encoder.WriteUint64(payload.timestamp)
	}

	return encoder.Buffer(), nil
}

var (
	ErrUnpackRecoveryKey   = errors.New("sbc/msgpack: recovery key unpack failed")
	ErrUnpackRecoveryKeyV2 = errors.New("sbc/msgpack: recovery key version 2 unpack failed")
	ErrUnpackBlobPayload   = errors.New("sbc/msgpack: blob payload unpack failed")
	ErrUnpackBackupPayload = errors.New("sbc/msgpack: backup payload unpack failed")
)

func unmarshalRecoveryKey(b []byte) ([]byte, error) {
	decoder := msgpack.NewDecoder(b)
	size, err := decoder.ReadArray()
	if err != nil {
		return nil, err
	}
	if size != 2 {
		return nil, ErrUnpackRecoveryKey
	}
	version, err := decoder.ReadUint()
	if err != nil {
		return nil, err
	}
	key, err := decoder.ReadBinary()
	if err != nil {
		return nil, err
	}
	if version != 1 || len(key) != 0x10 {
		return nil, ErrUnpackRecoveryKey
	}
	return key, nil
}

type recoveryKeyV2 struct {
	timestamp    uint64
	encryptedKey []byte
}

func unmarshalRecoveryKeyV2(b []byte) (*recoveryKeyV2, error) {
	decoder := msgpack.NewDecoder(b)
	size, err := decoder.ReadArray()
	if err != nil {
		return nil, err
	}
	if size != 3 {
		return nil, ErrUnpackRecoveryKeyV2
	}
	version, err := decoder.ReadUint()
	if err != nil {
		return nil, err
	}
	timestamp, err := decoder.ReadUint64()
	if err != nil {
		return nil, err
	}
	key, err := decoder.ReadBinary()
	if err != nil {
		return nil, err
	}
	if version != 2 || len(key) != 0x20 {
		return nil, ErrUnpackRecoveryKeyV2
	}
	return &recoveryKeyV2{
		timestamp:    timestamp,
		encryptedKey: key,
	}, nil
}

type field uint8

const (
	fieldNone field = 0

	fieldE2EEKey field = 1 << 0

	fieldBackupPin field = 1 << 1
	fieldMasterKey field = 1 << 2
)

func (f field) has(flag field) bool {
	return f&flag != 0
}

func (f field) extra() int {
	elem := 0
	if f.has(fieldBackupPin) {
		elem++
	}
	if f.has(fieldMasterKey) {
		elem++
	}
	return elem
}

type blobPayload struct {
	e2eeKeyIds []int32
	timestamp  uint64

	encryptedData []byte

	meta field
}

func unmarshalBlobPayload(b []byte) (*blobPayload, error) {
	decoder := msgpack.NewDecoder(b)
	size, err := decoder.ReadArray()
	if err != nil {
		return nil, err
	}
	if size != 3 {
		return nil, ErrUnpackBlobPayload
	}
	objType, err := decoder.ReadUint()
	if err != nil {
		return nil, err
	}
	if objType != 1 {
		return nil, errors.New("sbc/msgpack: backup keys contained an unknown object type")
	}

	elemSize, err := decoder.ReadArray()
	if err != nil {
		return nil, err
	}

	keyIds := make([]int32, elemSize)

	var payload blobPayload

	for i := 0; i < elemSize; i++ {
		v, err := decoder.ReadArray()
		if err != nil {
			return nil, err
		}
		keyType, err := decoder.ReadUint()
		if err != nil {
			return nil, err
		}
		switch BackupKeyType(keyType) {
		case BackupKeyTypeE2eeKey:
			if v != 2 {
				return nil, errors.New("sbc/msgpack: invalid data")
			}
			keyId, err := decoder.ReadInt32()
			if err != nil {
				return nil, err
			}
			keyIds[i] = keyId
		case BackupKeyTypeBackupPin:
			if v != 1 {
				return nil, errors.New("sbc/msgpack: invalid data")
			}
			payload.meta |= fieldBackupPin
		case BackupKeyTypeBackupMasterKey:
			if v != 2 {
				return nil, errors.New("sbc/msgpack: invalid data")
			}
			timestamp, err := decoder.ReadUint64()
			if err != nil {
				return nil, err
			}
			payload.timestamp = timestamp
			payload.meta |= fieldMasterKey
		}
	}

	data, err := decoder.ReadBinary()
	if err != nil {
		return nil, err
	}

	keyIds = keyIds[:len(keyIds)-payload.meta.extra()]

	payload.e2eeKeyIds = keyIds
	payload.encryptedData = data

	return &payload, nil
}

type keySlots struct {
	e2eeKeys  [][]byte
	pin       string
	masterKey []byte
}

func unmarshalBackupKeySlots(b []byte, f field) (*keySlots, error) {
	decoder := msgpack.NewDecoder(b)
	size, err := decoder.ReadArray()
	if err != nil {
		return nil, err
	}

	keySize := size - f.extra()

	slots := keySlots{
		e2eeKeys: make([][]byte, keySize),
	}

	for i := 0; i < keySize; i++ {
		key, err := decoder.ReadBinary()
		if err != nil {
			return nil, err
		}
		slots.e2eeKeys[i] = key
	}

	if !f.has(fieldBackupPin | fieldMasterKey) {
		return &slots, nil
	}

	if f.has(fieldBackupPin) {
		pin, err := decoder.ReadString()
		if err != nil {
			return nil, err
		}
		slots.pin = pin
	}

	if f.has(fieldMasterKey) {
		masterKey, err := decoder.ReadBinary()
		if err != nil {
			return nil, err
		}
		slots.masterKey = masterKey
	}

	return &slots, nil
}

type backupPayload struct {
	payloadType PayloadType
	metaData    []uint64
	nonce       []byte
	publicKey   []byte
	data        []byte
}

func unmarshalBackupPayload(b []byte) (*backupPayload, error) {
	decoder := msgpack.NewDecoder(b)
	size, err := decoder.ReadArray()
	if err != nil {
		return nil, err
	}
	if size < 5 {
		return nil, errors.New("sbc/msgpack: invalid data")
	}
	version, err := decoder.ReadUint()
	if err != nil {
		return nil, err
	}
	if version != 2 {
		return nil, ErrUnpackBackupPayload
	}
	var payload backupPayload
	pt, err := decoder.ReadUint()
	if err != nil {
		return nil, err
	}
	payloadType := PayloadType(pt)
	payload.payloadType = payloadType
	for i := 0; i < 2; i++ {
		timestamp, err := decoder.ReadUint64()
		if err != nil {
			return nil, err
		}
		payload.metaData = append(payload.metaData, timestamp)
	}
	if payloadType != PayloadTypeE2eeKey && payloadType != PayloadTypeInitialFullSyncKey {
		return nil, ErrUnpackBackupPayload
	}
	nonce, err := decoder.ReadBinary()
	if err != nil {
		return nil, err
	}
	payload.nonce = nonce
	if payloadType != PayloadTypeE2eeKey {
		data, err := decoder.ReadBinary()
		if err != nil {
			return nil, err
		}
		payload.data = data
	} else {
		pubKey, err := decoder.ReadBinary()
		if err != nil {
			return nil, err
		}
		payload.publicKey = pubKey
		data, err := decoder.ReadBinary()
		if err != nil {
			return nil, err
		}
		payload.data = data
	}
	return &payload, nil
}
