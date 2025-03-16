package msgpack

import "errors"

var (
	ErrUnpackMsgPack = errors.New("sbc/msgpack: data unpack failure")
	ErrPackMsgPack   = errors.New("sbc/msgpack: data pack failure")
)
