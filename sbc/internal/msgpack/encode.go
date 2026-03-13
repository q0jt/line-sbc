package msgpack

import (
	"bytes"
	"encoding/binary"
)

type Encoder struct {
	buf *bytes.Buffer
}

func NewEncoder() *Encoder {
	buf := new(bytes.Buffer)
	return &Encoder{buf: buf}
}

func (e *Encoder) Buffer() []byte {
	dst := e.buf.Bytes()
	e.buf.Reset()
	return dst
}

func (e *Encoder) WriteDirect(p []byte) {
	e.buf.Write(p)
}

func (e *Encoder) writeByteDirect(c byte) {
	e.buf.WriteByte(c)
}

func (e *Encoder) WriteArraySize(size uint8) {
	e.buf.WriteByte(0x9<<4 | size)
}

func (e *Encoder) WriteBinary(b []byte) error {
	size := len(b)
	switch {
	case size < (1<<8)-1:
		e.writeByteDirect(0xc4)
		e.writeByteDirect(byte(size))
	case size < (1<<16)-1:
		e.writeByteDirect(0xc5)
		length := make([]byte, 2)
		binary.LittleEndian.PutUint16(length, uint16(size))
		e.WriteDirect(length)
	case size < (1<<32)-1:
		e.writeByteDirect(0xc6)
		length := uint32ToBytes(uint32(size))
		e.WriteDirect(length)
	default:
		return ErrUnpackData
	}
	e.WriteDirect(b)
	return nil
}

func (e *Encoder) WriteFixUint(c byte) error {
	if c&0x80 != 0 {
		return ErrPackData
	}
	e.writeByteDirect(c)
	return nil
}

func (e *Encoder) WriteUint32(v uint32) {
	e.writeByteDirect(0xce)
	val := uint32ToBytes(v)
	e.WriteDirect(val)
}

func (e *Encoder) WriteUint64(v uint64) {
	e.writeByteDirect(0xcf)
	val := make([]byte, 8)
	binary.BigEndian.PutUint64(val, v)
	e.WriteDirect(val)
}

func uint32ToBytes(v uint32) []byte {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, v)
	return val
}
