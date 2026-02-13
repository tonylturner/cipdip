package core

import (
	"github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/enip"
	"github.com/tonylturner/cipdip/internal/logging"
)

func parseENIPStream(buffer []byte, logger *logging.Logger) ([]enip.ENIPEncapsulation, []byte) {
	const headerSize = 24
	order := client.CurrentProtocolProfile().ENIPByteOrder
	frames := make([]enip.ENIPEncapsulation, 0)
	offset := 0

	for len(buffer[offset:]) >= headerSize {
		command := order.Uint16(buffer[offset : offset+2])
		if !isValidENIPCommand(command) {
			offset++
			continue
		}
		length := int(order.Uint16(buffer[offset+2 : offset+4]))
		total := headerSize + length
		if len(buffer[offset:]) < total {
			break
		}

		frame := buffer[offset : offset+total]
		encap, err := enip.DecodeENIP(frame)
		if err != nil {
			logger.Debug("Decode ENIP error: %v", err)
			offset++
			continue
		}
		frames = append(frames, encap)
		offset += total
	}

	if offset == 0 {
		return frames, buffer
	}
	remaining := make([]byte, len(buffer)-offset)
	copy(remaining, buffer[offset:])
	return frames, remaining
}

func isValidENIPCommand(cmd uint16) bool {
	switch cmd {
	case enip.ENIPCommandRegisterSession,
		enip.ENIPCommandUnregisterSession,
		enip.ENIPCommandSendRRData,
		enip.ENIPCommandSendUnitData,
		enip.ENIPCommandListIdentity,
		enip.ENIPCommandListServices,
		enip.ENIPCommandListInterfaces:
		return true
	default:
		return false
	}
}
