package msgpack

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type encoder struct {
	buf *bytes.Buffer
}

func newEncoder() *encoder {
	return &encoder{buf: new(bytes.Buffer)}
}

type KeyWrap struct {
	certKey []byte
	seed    []byte
}

func NewKeyWrap(ck, seed []byte) *KeyWrap {
	return &KeyWrap{certKey: ck, seed: seed}
}

func EncodeClaimWithKeyWarp(kw *KeyWrap, tempKey, pin []byte, timestamp int64) ([]byte, error) {
	return EncodeClaim(kw, tempKey, pin, timestamp)
}

func EncodeClaim(kw *KeyWrap, tempKey, pin []byte, timestamp int64) ([]byte, error) {
	e := newEncoder()
	claim, err := e.packClaim(kw, tempKey, pin, timestamp)
	if err != nil {
		return nil, err
	}
	return claim, nil
}

func (e *encoder) packArraySize(size uint8) {
	e.buf.WriteByte(0x9<<4 | size)
}

func (e *encoder) writeBin(b []byte) {
	size := len(b)
	if size < 0xff {
		e.buf.WriteByte(0xc4)
		e.buf.WriteByte(byte(size))
	} else if size < 0xffff {
		e.buf.WriteByte(0xc5)
		length := make([]byte, 2)
		binary.LittleEndian.PutUint16(length, uint16(size))
		e.buf.Write(length)
	}
	e.buf.Write(b)
}

func (e *encoder) packClaim(kw *KeyWrap, tempKey, pin []byte, timestamp int64) ([]byte, error) {
	e.packArraySize(5)
	e.buf.WriteByte(2)
	e.buf.WriteByte(0xcf)
	ut := make([]byte, 8)
	binary.BigEndian.PutUint64(ut, uint64(timestamp))
	e.buf.Write(ut)
	e.writeBin(tempKey)
	e.packArraySize(1)
	if err := e.packKeyWrap(kw); err != nil {
		return nil, err
	}
	e.writeBin(pin)

	return e.buf.Bytes(), nil
}

func (e *encoder) packKeyWrap(kw *KeyWrap) error {
	if kw == nil {
		return errors.New("no KeyWrap")
	}
	if len(kw.certKey) != 0x40 {
		return errors.New("invalid public key size")
	}
	if size := len(kw.seed); size != 0x10 && size != 0x20 {
		return errors.New("invalid rng size")
	}

	e.packArraySize(2)

	e.writeBin(kw.certKey)
	e.writeBin(kw.seed)

	return nil
}
