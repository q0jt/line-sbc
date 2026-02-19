package msgpack

import (
	"bytes"
	"encoding/binary"
)

type Decoder struct {
	reader *bytes.Reader
	temp   [8]byte
}

func NewDecoder(b []byte) *Decoder {
	r := bytes.NewReader(b)
	return &Decoder{reader: r}
}

func (d *Decoder) readFull(b []byte) error {
	_, err := d.reader.Read(b)
	return err
}

func (d *Decoder) read(size int) ([]byte, error) {
	dst := make([]byte, size)
	if err := d.readFull(dst); err != nil {
		return nil, err
	}
	return dst, nil
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
		return 0, ErrUnpackData
	}
	if err := d.readFull(d.temp[:4]); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint32(d.temp[:4])
	return int32(v), nil
}

func (d *Decoder) ReadUint64() (uint64, error) {
	c, err := d.byte()
	if err != nil {
		return 0, err
	}
	if c != 0xcf {
		return 0, ErrUnpackData
	}
	if err := d.readFull(d.temp[:]); err != nil {
		return 0, err
	}
	v := binary.BigEndian.Uint64(d.temp[:])
	return v, nil
}

func (d *Decoder) ReadBinary() ([]byte, error) {
	c, err := d.byte()
	if err != nil {
		return nil, err
	}
	var size uint16
	switch c {
	case 0xc4:
		n, err := d.byte()
		if err != nil {
			return nil, err
		}
		size = uint16(n)
	case 0xc5:
		if err := d.readFull(d.temp[:2]); err != nil {
			return nil, err
		}
		size = binary.BigEndian.Uint16(d.temp[:2])
	default:
		return nil, ErrUnpackData
	}
	return d.read(int(size))
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
	dst, err := d.read(size)
	if err != nil {
		return "", err
	}
	return string(dst), nil
}

func (d *Decoder) ReadArray() (int, error) {
	c, err := d.byte()
	if err != nil {
		return -1, ErrUnpackData
	}
	if (c & 0xF0) == 0x90 {
		return int(c & 0x0F), nil
	}
	// array16, array32 support might be necessary
	return -1, ErrUnpackData
}
