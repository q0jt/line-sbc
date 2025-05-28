package msgpack

import "errors"

var (
	ErrUnpackData = errors.New("sbc/msgpack: data unpack failure")
	ErrPackData   = errors.New("sbc/msgpack: data pack failure")
)
