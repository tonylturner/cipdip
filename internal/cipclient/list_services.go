package cipclient

import "fmt"

// BuildListServices builds a ListServices encapsulation.
func BuildListServices(senderContext [8]byte) []byte {
	encap := ENIPEncapsulation{
		Command:       ENIPCommandListServices,
		Length:        0,
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          nil,
	}
	return EncodeENIP(encap)
}

// BuildListInterfaces builds a ListInterfaces encapsulation.
func BuildListInterfaces(senderContext [8]byte) []byte {
	encap := ENIPEncapsulation{
		Command:       ENIPCommandListInterfaces,
		Length:        0,
		SessionID:     0,
		Status:        0,
		SenderContext: senderContext,
		Options:       0,
		Data:          nil,
	}
	return EncodeENIP(encap)
}

// ParseListServicesResponse parses a ListServices response and returns CPF items.
func ParseListServicesResponse(data []byte) ([]CPFItem, error) {
	return parseListResponse(data, ENIPCommandListServices, "ListServices")
}

// ParseListInterfacesResponse parses a ListInterfaces response and returns CPF items.
func ParseListInterfacesResponse(data []byte) ([]CPFItem, error) {
	return parseListResponse(data, ENIPCommandListInterfaces, "ListInterfaces")
}

func parseListResponse(data []byte, expectedCommand uint16, name string) ([]CPFItem, error) {
	encap, err := DecodeENIP(data)
	if err != nil {
		return nil, err
	}
	if encap.Command != expectedCommand {
		return nil, fmt.Errorf("%s response command mismatch: 0x%04X", name, encap.Command)
	}
	if encap.Status != ENIPStatusSuccess {
		return nil, fmt.Errorf("%s response status: 0x%08X", name, encap.Status)
	}
	if encap.Length != uint16(len(encap.Data)) {
		return nil, fmt.Errorf("%s response length mismatch: %d vs %d", name, encap.Length, len(encap.Data))
	}
	if len(encap.Data) == 0 {
		return nil, nil
	}
	items, err := ParseCPFItems(encap.Data)
	if err != nil {
		return nil, fmt.Errorf("%s response CPF items: %w", name, err)
	}
	return items, nil
}
