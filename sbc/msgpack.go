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

func marshalBlobPayloadMetaData(payload *msgpack.BlobPayload) ([]byte, error) {
	if payload == nil {
		return nil, errors.New("no BlobPayload")
	}

	encoder := msgpack.NewEncoder()

	keyIds := payload.MetaData
	size := len(keyIds)
	isMig := payload.ContainsPin()
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
