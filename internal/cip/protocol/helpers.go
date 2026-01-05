package protocol

import "encoding/binary"

func appendUint16(order binary.ByteOrder, b []byte, v uint16) []byte {
	var buf [2]byte
	order.PutUint16(buf[:], v)
	return append(b, buf[:]...)
}

func appendUint32(order binary.ByteOrder, b []byte, v uint32) []byte {
	var buf [4]byte
	order.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}
