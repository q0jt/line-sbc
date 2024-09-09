package msgpack

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
)

type decoder struct {
	buf *bytes.Reader
	off int
}

func newDecoder(b []byte) *decoder {
	return &decoder{buf: bytes.NewReader(b)}
}

func (d *decoder) magic() (byte, error) {
	return d.buf.ReadByte()
}

func (d *decoder) read(size int) ([]byte, error) {
	out := make([]byte, size)
	if _, err := d.buf.Read(out); err != nil {
		return nil, err
	}
	return out, nil
}

func (d *decoder) unpackArray() int {
	magic, err := d.magic()
	if err != nil {
		return -1
	}
	if (magic & 0xF0) == 0x90 {
		return int(magic & 0x0F)
	}
	if magic != 0xDD && magic != 0xDC {
		return -1
	}
	size, err := d.read(1)
	if err != nil {
		return -1
	}
	if magic == 0xDD {
		v6 := binary.BigEndian.Uint32(size)
		d.off += 4
		return int(v6)
	} else if magic == 0xDC {
		v6 := binary.BigEndian.Uint16(size)
		d.off += 2
		return int(v6)
	}
	return -1
}

func (d *decoder) unpackUint() (uint, error) {
	c, err := d.read(1)
	if err != nil {
		return 0, err
	}
	if c[0]&0x80 != 0 {
		return 0, errors.New("sbc/msgpack: only accept positive int")
	}
	return uint(c[0]), nil
}

func unpackUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}

func (d *decoder) unpackBin() ([]byte, error) {
	c, err := d.read(1)
	if err != nil {
		return nil, err
	}
	switch c[0] {
	case 0xc4:
		n, err := d.read(1)
		if err != nil {
			return nil, err
		}
		size := int(n[0])
		return d.read(size)
	case 0xc5:
		n, err := d.read(2)
		if err != nil {
			return nil, err
		}
		size := unpackUint16(n)
		return d.read(int(size))
	}
	return nil, errors.New("sbc/pack.go: invalid data")
}

func (d *decoder) unpackInt32() int32 {
	c, err := d.read(1)
	if err != nil {
		return -1
	}
	if c[0] != 0xce {
		return -1
	}
	cc, err := d.read(4)
	if err != nil {
		return -1
	}
	v := binary.BigEndian.Uint32(cc)
	return int32(v)
}

func (d *decoder) unpackRecoveryKey() ([]byte, error) {
	size := d.unpackArray()
	if size != 2 {
		return nil, errors.New("error")
	}
	objType, err := d.unpackUint()
	if err != nil {
		return nil, err
	}
	if objType != 1 {
		return nil, errors.New("eer")
	}
	return d.unpackBin()
}

func UnpackRecoveryKey(b []byte) ([]byte, error) {
	decoder := newDecoder(b)
	key, err := decoder.unpackRecoveryKey()
	if err != nil {
		return nil, err
	}
	if len(key) != 0x10 {
		return nil, errors.New("error")
	}
	return key, nil
}

type BlobPayload struct {
	metaData []byte
	payload  []byte
}

func (d *decoder) unpackBlobPayload() ([]byte, error) {
	if d.unpackArray() != 3 {
		return nil, errors.New("error: 1: unpackArray")
	}
	objType, err := d.unpackUint()
	if err != nil {
		return nil, err
	}
	if objType != 1 {
		return nil, errors.New("error: 2: unpackUint")
	}
	metaContainerSize := d.unpackArray()
	for i := 0; i < metaContainerSize; i++ {
		d.unpackArray()
		fmt.Println(d.unpackUint())
		fmt.Println(d.unpackInt32())
	}
	return d.unpackBin()
}

func UnpackBlobPayload(b []byte) {
	decoder := newDecoder(b)
	s, _ := decoder.unpackBlobPayload()
	fmt.Println(hex.EncodeToString(s))
}
