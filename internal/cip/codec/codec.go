package codec

import "encoding/binary"

// PutUint16 writes a uint16 to dst using the provided byte order.
func PutUint16(order binary.ByteOrder, dst []byte, value uint16) {
	order.PutUint16(dst, value)
}

// PutUint32 writes a uint32 to dst using the provided byte order.
func PutUint32(order binary.ByteOrder, dst []byte, value uint32) {
	order.PutUint32(dst, value)
}

// PutUint64 writes a uint64 to dst using the provided byte order.
func PutUint64(order binary.ByteOrder, dst []byte, value uint64) {
	order.PutUint64(dst, value)
}

// AppendUint16 appends a uint16 to dst using the provided byte order.
func AppendUint16(order binary.ByteOrder, dst []byte, value uint16) []byte {
	var buf [2]byte
	order.PutUint16(buf[:], value)
	return append(dst, buf[:]...)
}

// AppendUint32 appends a uint32 to dst using the provided byte order.
func AppendUint32(order binary.ByteOrder, dst []byte, value uint32) []byte {
	var buf [4]byte
	order.PutUint32(buf[:], value)
	return append(dst, buf[:]...)
}

// AppendUint64 appends a uint64 to dst using the provided byte order.
func AppendUint64(order binary.ByteOrder, dst []byte, value uint64) []byte {
	var buf [8]byte
	order.PutUint64(buf[:], value)
	return append(dst, buf[:]...)
}
