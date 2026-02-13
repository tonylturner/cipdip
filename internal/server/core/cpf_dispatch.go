package core

import (
	"fmt"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/enip"
)

func (s *Server) parseSendRRData(data []byte) ([]byte, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("SendRRData data too short: %d bytes", len(data))
	}
	payload := data[6:]
	cpfStrict := boolValue(s.config.ENIP.CPF.Strict, true)
	allowMissing := boolValue(s.config.ENIP.CPF.AllowMissingItems, false)
	allowExtra := boolValue(s.config.ENIP.CPF.AllowExtraItems, false)
	allowReorder := boolValue(s.config.ENIP.CPF.AllowItemReorder, true)

	items, err := enip.ParseCPFItems(payload)
	if err != nil {
		if !cpfStrict && allowMissing {
			return payload, nil
		}
		return nil, err
	}
	if len(items) == 0 {
		if allowMissing {
			return payload, nil
		}
		return nil, fmt.Errorf("missing CPF items")
	}
	if !allowExtra && len(items) != 2 {
		return nil, fmt.Errorf("unexpected CPF item count: %d", len(items))
	}
	if !allowReorder {
		if len(items) < 2 || items[0].TypeID != enip.CPFItemNullAddress || items[1].TypeID != enip.CPFItemUnconnectedData {
			return nil, fmt.Errorf("CPF items out of order")
		}
	}
	for _, item := range items {
		if item.TypeID == enip.CPFItemUnconnectedData {
			return item.Data, nil
		}
	}
	if allowMissing {
		return payload, nil
	}
	return nil, fmt.Errorf("missing unconnected data item")
}

func (s *Server) parseSendUnitData(data []byte) (uint32, []byte, error) {
	if len(data) < 4 {
		return 0, nil, fmt.Errorf("SendUnitData data too short: %d bytes", len(data))
	}
	payload := data
	cpfStrict := boolValue(s.config.ENIP.CPF.Strict, true)
	allowMissing := boolValue(s.config.ENIP.CPF.AllowMissingItems, false)
	allowExtra := boolValue(s.config.ENIP.CPF.AllowExtraItems, false)
	allowReorder := boolValue(s.config.ENIP.CPF.AllowItemReorder, true)

	if len(data) >= 6 {
		payload = data[6:]
	}
	items, err := enip.ParseCPFItems(payload)
	if err != nil {
		if !cpfStrict && allowMissing {
			connID := cipclient.CurrentProtocolProfile().ENIPByteOrder.Uint32(data[:4])
			return connID, data[4:], nil
		}
		return 0, nil, err
	}
	if len(items) == 0 {
		if allowMissing {
			connID := cipclient.CurrentProtocolProfile().ENIPByteOrder.Uint32(data[:4])
			return connID, data[4:], nil
		}
		return 0, nil, fmt.Errorf("missing CPF items")
	}
	if !allowExtra && len(items) != 2 {
		return 0, nil, fmt.Errorf("unexpected CPF item count: %d", len(items))
	}
	if !allowReorder {
		if len(items) < 2 || items[0].TypeID != enip.CPFItemConnectedAddress || items[1].TypeID != enip.CPFItemConnectedData {
			return 0, nil, fmt.Errorf("CPF items out of order")
		}
	}

	var connID uint32
	var cipData []byte
	order := cipclient.CurrentProtocolProfile().ENIPByteOrder
	for _, item := range items {
		switch item.TypeID {
		case enip.CPFItemConnectedAddress:
			if len(item.Data) < 4 {
				return 0, nil, fmt.Errorf("connected address item too short")
			}
			connID = order.Uint32(item.Data[:4])
		case enip.CPFItemConnectedData:
			cipData = item.Data
		}
	}
	if connID == 0 || cipData == nil {
		if allowMissing {
			connID = order.Uint32(data[:4])
			return connID, data[4:], nil
		}
		return 0, nil, fmt.Errorf("missing connected items")
	}
	return connID, cipData, nil
}
