package sbc

import (
	"errors"
	"github.com/q0jt/line-sbc/sbc/internal/msgpack"
)

func marshalKeyWrap(certKey, enc []byte) ([]byte, error) {
	if len(certKey) != 0x40 {
		return nil, errors.New("sbc/msgpack: invalid public key size")
	}
	if size := len(enc); size != 0x10 && size != 0x20 {
		return nil, errors.New("sbc/msgpack: invalid rng size")
	}

	encoder := msgpack.NewEncoder()

	encoder.WriteArraySize(2)
	encoder.WriteBinary(certKey)
	encoder.WriteBinary(enc)

	return encoder.Buffer(), nil
}

func marshalClaim(wrapKey, tempKey, pin []byte, timestamp int64) ([]byte, error) {
	encoder := msgpack.NewEncoder()
	encoder.WriteArraySize(5)
	if err := encoder.WriteUint(2); err != nil {
		return nil, err
	}
	encoder.WriteUint64(uint64(timestamp))
	encoder.WriteBinary(tempKey)
	encoder.WriteArraySize(1)
	encoder.WriteDirect(wrapKey)
	encoder.WriteBinary(pin)
	return encoder.Buffer(), nil
}

func marshalClaimV3(mid, passwd []byte, envelope *keyEnvelope, timestamp int64) ([]byte, error) {
	encoder := msgpack.NewEncoder()
	encoder.WriteArraySize(7)
	if err := encoder.WriteUint(3); err != nil {
		return nil, err
	}
	encoder.WriteBinary(mid)
	encoder.WriteUint64(uint64(timestamp))
	encoder.WriteBinary(envelope.tempKey)
	encoder.WriteArraySize(1)
	encoder.WriteDirect(envelope.wrapKey)
	// factorType
	if err := encoder.WriteUint(1); err != nil {
		return nil, err
	}
	encoder.WriteBinary(passwd)
	return encoder.Buffer(), nil
}

func marshalBlobPayloadMetaData(payload *blobPayload) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("sbc/msgpack: no blob payload")
	}

	encoder := msgpack.NewEncoder()

	keyIds := payload.MetaData
	size := len(keyIds)
	isMig := payload.isMigration
	if isMig {
		size++
	}
	encoder.WriteArraySize(uint8(size))
	for _, keyId := range keyIds {
		encoder.WriteArraySize(2)
		if err := encoder.WriteUint(0x01); err != nil {
			return nil, err
		}
		encoder.WriteUint32(uint32(keyId))
	}
	if isMig {
		encoder.WriteArraySize(1)
		if err := encoder.WriteUint(2); err != nil {
			return nil, err
		}
	}
	return encoder.Buffer(), nil
}

var (
	ErrUnpackRecoveryKey   = errors.New("sbc/msgpack: recovery key unpack failed")
	ErrUnpackRecoveryKeyV2 = errors.New("sbc/msgpack: recovery key version 2 unpack failed")
	ErrUnpackBlobPayload   = errors.New("sbc/msgpack: blob payload unpack failed")
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

type blobPayload struct {
	MetaData         []int32
	EncryptedSection []byte

	isMigration bool
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

	metaContainerSize, err := decoder.ReadArray()
	if err != nil {
		return nil, err
	}

	keyIds := make([]int32, metaContainerSize)

	var payload blobPayload

	for i := 0; i < metaContainerSize; i++ {
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
			payload.isMigration = true
		case BackupKeyTypeBackupMasterKey:
			if v != 2 {
				return nil, errors.New("sbc/msgpack: invalid data")
			}
		}
	}

	enc, err := decoder.ReadBinary()
	if err != nil {
		return nil, err
	}

	if payload.isMigration {
		keyIds = keyIds[:len(keyIds)-1]
	}

	payload.MetaData = keyIds
	payload.EncryptedSection = enc

	return &payload, nil
}

type keySlots struct {
	e2eeKeys  [][]byte
	pin       string
	masterKey []byte
}

func unmarshalBackupKeySlots(b []byte, mig bool) (*keySlots, error) {
	decoder := msgpack.NewDecoder(b)
	size, err := decoder.ReadArray()
	if err != nil {
		return nil, err
	}
	if mig {
		size--
	}

	slots := keySlots{
		e2eeKeys: make([][]byte, size),
	}

	for i := 0; i < size; i++ {
		data, err := decoder.ReadBinary()
		if err != nil {
			return nil, err
		}
		slots.e2eeKeys[i] = data
	}
	if !mig {
		return &slots, nil
	}
	pin, err := decoder.ReadString()
	if err != nil {
		return nil, err
	}
	slots.pin = pin
	return &slots, nil
}
