package client

import (
	"fmt"
	"github.com/tonylturner/cipdip/internal/enip"
)

// BuildListServices builds a ListServices encapsulation.
func BuildListServices(senderContext [8]byte) []byte {
	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandListServices,
		Length:        0,
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          nil,
	}
	return enip.EncodeENIP(encap)
}

// BuildListInterfaces builds a ListInterfaces encapsulation.
func BuildListInterfaces(senderContext [8]byte) []byte {
	encap := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandListInterfaces,
		Length:        0,
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          nil,
	}
	return enip.EncodeENIP(encap)
}

// ParseListServicesResponse parses a ListServices response and returns CPF items.
func ParseListServicesResponse(data []byte) ([]enip.CPFItem, error) {
	return parseListResponse(data, enip.ENIPCommandListServices, "ListServices")
}

// ParseListInterfacesResponse parses a ListInterfaces response and returns CPF items.
func ParseListInterfacesResponse(data []byte) ([]enip.CPFItem, error) {
	return parseListResponse(data, enip.ENIPCommandListInterfaces, "ListInterfaces")
}

func parseListResponse(data []byte, expectedCommand uint16, name string) ([]enip.CPFItem, error) {
	encap, err := enip.DecodeENIP(data)
	if err != nil {
		return nil, err
	}
	if encap.Command != expectedCommand {
		return nil, fmt.Errorf("%s response command mismatch: 0x%04X", name, encap.Command)
	}
	if encap.Status != enip.ENIPStatusSuccess {
		return nil, fmt.Errorf("%s response status: 0x%08X", name, encap.Status)
	}
	if encap.Length != uint16(len(encap.Data)) {
		return nil, fmt.Errorf("%s response length mismatch: %d vs %d", name, encap.Length, len(encap.Data))
	}
	if len(encap.Data) == 0 {
		return nil, nil
	}
	items, err := enip.ParseCPFItems(encap.Data)
	if err != nil {
		return nil, fmt.Errorf("%s response CPF items: %w", name, err)
	}
	return items, nil
}

