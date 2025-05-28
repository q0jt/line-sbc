package msgpack

import (
	"bytes"
	"encoding/binary"
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
		return 0, ErrUnpackData
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

func (d *Decoder) ReadUint64() (uint64, error) {
	c, err := d.byte()
	if err != nil {
		return 0, err
	}
	if c != 0xcf {
		return 0, err
	}
	data, err := d.read(8)
	if err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(data)
	return v, nil
}

func (d *Decoder) ReadBinary() ([]byte, error) {
	c, err := d.byte()
	if err != nil {
		return nil, err
	}
	switch c {
	case 0xc4:
		size, err := d.byte()
		if err != nil {
			return nil, err
		}
		return d.read(int(size))
	case 0xc5:
		n, err := d.read(2)
		if err != nil {
			return nil, err
		}
		size := binary.BigEndian.Uint16(n)
		return d.read(int(size))
	}
	return nil, ErrUnpackData
}

func (d *Decoder) ReadString() (string, error) {
	c, err := d.byte()
	if err != nil {
		return "", err
	}
	if (c>>0x5)&0x07 != 0x5 {
		return "", ErrUnpackData
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
		return -1, ErrUnpackData
	}
	if (c & 0xF0) == 0x90 {
		return int(c & 0x0F), nil
	}
	if c != 0xDD && c != 0xDC {
		return -1, ErrUnpackData
	}
	size, err := d.read(1)
	if err != nil {
		return -1, ErrUnpackData
	}
	if c == 0xDD {
		v := binary.BigEndian.Uint32(size)
		return int(v), nil
	}
	v := binary.BigEndian.Uint16(size)
	return int(v), nil
}
