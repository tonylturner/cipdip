package cipclient

import "encoding/binary"

func currentENIPByteOrder() binary.ByteOrder {
	return CurrentProtocolProfile().ENIPByteOrder
}

func currentCIPByteOrder() binary.ByteOrder {
	return CurrentProtocolProfile().CIPByteOrder
}

func appendUint16(order binary.ByteOrder, b []byte, v uint16) []byte {
	var tmp [2]byte
	order.PutUint16(tmp[:], v)
	return append(b, tmp[:]...)
}

func appendUint32(order binary.ByteOrder, b []byte, v uint32) []byte {
	var tmp [4]byte
	order.PutUint32(tmp[:], v)
	return append(b, tmp[:]...)
}
