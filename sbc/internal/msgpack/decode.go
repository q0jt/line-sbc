package msgpack

import (
	"bytes"
	"encoding/binary"
	"errors"
)

type Decoder struct {
	reader *bytes.Reader
}

func NewDecoder(b []byte) *Decoder {
	r := bytes.NewReader(b)
	return &Decoder{reader: r}
}

func (d *Decoder) read(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := d.reader.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

func (d *Decoder) byte() (byte, error) {
	return d.reader.ReadByte()
}

func (d *Decoder) ReadUint() (uint, error) {
	c, err := d.byte()
	if err != nil {
		return 0, err
	}
	if c&0x80 != 0 {
		return 0, errors.New("sbc/msgpack: only accept positive int")
	}
	return uint(c), nil
}

func (d *Decoder) ReadInt32() (int32, error) {
	c, err := d.byte()
	if err != nil {
		return 0, err
	}
	if c != 0xce {
		return 0, err
	}
	cc, err := d.read(4)
	if err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(cc)
	return int32(v), nil
}

func (d *Decoder) ReadBinary() ([]byte, error) {
	c, err := d.byte()
	if err != nil {
		return nil, err
	}
	switch c {
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
		size := binary.BigEndian.Uint16(n)
		return d.read(int(size))
	}
	return nil, errors.New("sbc/msgpack: invalid binary data")
}

func (d *Decoder) ReadString() (string, error) {
	c, err := d.byte()
	if err != nil {
		return "", err
	}
	if (c>>0x5)&0x07 != 0x5 {
		return "", errors.New("err")
	}
	size := int(c & 0x1F)
	str, err := d.read(size)
	if err != nil {
		return "", err
	}
	return string(str), nil
}

func (d *Decoder) ReadArray() (int, error) {
	c, err := d.byte()
	if err != nil {
		return -1, errors.New("error while reading array")
	}
	if (c & 0xF0) == 0x90 {
		return int(c & 0x0F), nil
	}
	if c != 0xDD && c != 0xDC {
		return -1, errors.New("error while reading array")
	}
	size, err := d.read(1)
	if err != nil {
		return -1, errors.New("error while reading array")
	}
	if c == 0xDD {
		v6 := binary.BigEndian.Uint32(size)
		return int(v6), nil
	}
	v6 := binary.BigEndian.Uint16(size)
	return int(v6), nil
}
