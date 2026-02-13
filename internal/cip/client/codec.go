package client

import (
	"encoding/binary"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/enip"
)

func currentENIPByteOrder() binary.ByteOrder {
	opts := enip.CurrentOptions()
	if opts.ByteOrder != nil {
		return opts.ByteOrder
	}
	return CurrentProtocolProfile().ENIPByteOrder
}

func currentCIPByteOrder() binary.ByteOrder {
	opts := protocol.CurrentOptions()
	if opts.ByteOrder != nil {
		return opts.ByteOrder
	}
	return CurrentProtocolProfile().CIPByteOrder
}

// append helpers moved to internal/cip/codec

