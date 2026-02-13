package standard

import (
	"context"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/codec"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/config"
)

type IdentityHandler struct {
	cfg *config.ServerConfig
}

func NewIdentityHandler(cfg *config.ServerConfig) *IdentityHandler {
	return &IdentityHandler{cfg: cfg}
}

func (h *IdentityHandler) HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	if req.Path.Instance != 0x0001 {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x05,
			Path:    req.Path,
		}, nil
	}

	switch req.Service {
	case spec.CIPServiceGetAttributeSingle:
		payload, ok := h.identityAttributePayload(req.Path.Attribute)
		if !ok {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x14,
				Path:    req.Path,
			}, nil
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, nil
	case spec.CIPServiceGetAttributeAll:
		payload := h.identityAllPayload()
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, nil
	default:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}, nil
	}
}

func (h *IdentityHandler) identityAttributePayload(attribute uint16) ([]byte, bool) {
	vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName := h.identityValues()
	order := cipclient.CurrentProtocolProfile().CIPByteOrder

	switch attribute {
	case 1:
		payload := make([]byte, 2)
		codec.PutUint16(order, payload, vendorID)
		return payload, true
	case 2:
		payload := make([]byte, 2)
		codec.PutUint16(order, payload, deviceType)
		return payload, true
	case 3:
		payload := make([]byte, 2)
		codec.PutUint16(order, payload, productCode)
		return payload, true
	case 4:
		return []byte{revMajor, revMinor}, true
	case 5:
		payload := make([]byte, 2)
		codec.PutUint16(order, payload, status)
		return payload, true
	case 6:
		payload := make([]byte, 4)
		codec.PutUint32(order, payload, serial)
		return payload, true
	case 7:
		return encodeShortString(productName), true
	default:
		return nil, false
	}
}

func (h *IdentityHandler) identityAllPayload() []byte {
	vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName := h.identityValues()
	order := cipclient.CurrentProtocolProfile().CIPByteOrder

	payload := make([]byte, 0, 16)
	buf2 := make([]byte, 2)
	buf4 := make([]byte, 4)

	codec.PutUint16(order, buf2, vendorID)
	payload = append(payload, buf2...)
	codec.PutUint16(order, buf2, deviceType)
	payload = append(payload, buf2...)
	codec.PutUint16(order, buf2, productCode)
	payload = append(payload, buf2...)
	payload = append(payload, revMajor, revMinor)
	codec.PutUint16(order, buf2, status)
	payload = append(payload, buf2...)
	codec.PutUint32(order, buf4, serial)
	payload = append(payload, buf4...)
	payload = append(payload, encodeShortString(productName)...)

	return payload
}

func (h *IdentityHandler) identityValues() (uint16, uint16, uint16, uint8, uint8, uint16, uint32, string) {
	cfg := h.cfg.Server
	vendorID := cfg.IdentityVendorID
	deviceType := cfg.IdentityDeviceType
	productCode := cfg.IdentityProductCode
	revMajor := cfg.IdentityRevMajor
	revMinor := cfg.IdentityRevMinor
	status := cfg.IdentityStatus
	serial := cfg.IdentitySerial
	productName := cfg.IdentityProductName
	if productName == "" {
		if cfg.Name != "" {
			productName = cfg.Name
		} else {
			productName = "CIPDIP"
		}
	}
	if revMajor == 0 && revMinor == 0 {
		revMajor = 1
	}
	return vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName
}

func encodeShortString(value string) []byte {
	data := []byte(value)
	if len(data) > 255 {
		data = data[:255]
	}
	payload := make([]byte, 1+len(data))
	payload[0] = byte(len(data))
	copy(payload[1:], data)
	return payload
}
