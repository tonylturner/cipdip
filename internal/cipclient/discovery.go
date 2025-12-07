package cipclient

// Discovery support for ListIdentity

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

// DiscoveredDevice represents a device discovered via ListIdentity
type DiscoveredDevice struct {
	IP         string
	VendorID   uint16
	ProductID  uint16
	ProductName string
	SerialNumber uint32
	State      uint8
}

// DiscoverDevices sends ListIdentity requests via UDP broadcast and collects responses
func DiscoverDevices(ctx context.Context, iface string, timeout time.Duration) ([]DiscoveredDevice, error) {
	// Resolve broadcast address
	var broadcastAddr *net.UDPAddr
	var err error
	
	if iface != "" {
		// Use specific interface
		ief, err := net.InterfaceByName(iface)
		if err != nil {
			return nil, fmt.Errorf("interface %s: %w", iface, err)
		}
		
		addrs, err := ief.Addrs()
		if err != nil {
			return nil, fmt.Errorf("get interface addresses: %w", err)
		}
		
		// Find IPv4 address and calculate broadcast
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipnet.IP.To4() != nil {
					// Calculate broadcast address
					ip := ipnet.IP.To4()
					mask := ipnet.Mask
					broadcast := make(net.IP, 4)
					for i := range ip {
						broadcast[i] = ip[i] | ^mask[i]
					}
					broadcastAddr = &net.UDPAddr{
						IP:   broadcast,
						Port: 44818,
					}
					break
				}
			}
		}
		
		if broadcastAddr == nil {
			return nil, fmt.Errorf("no IPv4 address found on interface %s", iface)
		}
	} else {
		// Use global broadcast
		broadcastAddr, err = net.ResolveUDPAddr("udp", "255.255.255.255:44818")
		if err != nil {
			return nil, fmt.Errorf("resolve broadcast address: %w", err)
		}
	}

	// Create UDP socket
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen UDP: %w", err)
	}
	defer conn.Close()

	// Set read timeout
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set read deadline: %w", err)
	}

	// Build ListIdentity packet
	senderContext := [8]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	packet := BuildListIdentity(senderContext)

	// Send broadcast
	if _, err := conn.WriteToUDP(packet, broadcastAddr); err != nil {
		return nil, fmt.Errorf("send ListIdentity: %w", err)
	}

	// Collect responses
	var devices []DiscoveredDevice
	seenIPs := make(map[string]bool)
	
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		// Update read deadline
		remaining := time.Until(deadline)
		if remaining > 0 {
			conn.SetReadDeadline(time.Now().Add(remaining))
		}

		buffer := make([]byte, 1500) // Max UDP packet size
		n, addr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			// Check if it's a timeout
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				break
			}
			continue
		}

		// Skip if we've already seen this IP
		ipStr := addr.IP.String()
		if seenIPs[ipStr] {
			continue
		}
		seenIPs[ipStr] = true

		// Parse response
		device, err := parseListIdentityResponse(buffer[:n])
		if err != nil {
			// Skip invalid responses
			continue
		}

		device.IP = ipStr
		devices = append(devices, device)
	}

	return devices, nil
}

// parseListIdentityResponse parses a ListIdentity response
func parseListIdentityResponse(data []byte) (DiscoveredDevice, error) {
	var device DiscoveredDevice

	// Minimum ListIdentity response size is 24 (ENIP header) + 34 (ListIdentity data)
	if len(data) < 58 {
		return device, fmt.Errorf("response too short: %d bytes", len(data))
	}

	// Decode ENIP header
	encap, err := DecodeENIP(data)
	if err != nil {
		return device, fmt.Errorf("decode ENIP: %w", err)
	}

	if encap.Command != ENIPCommandListIdentity {
		return device, fmt.Errorf("unexpected command: 0x%04X", encap.Command)
	}

	if encap.Status != ENIPStatusSuccess {
		return device, fmt.Errorf("ENIP error status: 0x%08X", encap.Status)
	}

	// Parse ListIdentity data
	// ListIdentity response structure (from ENIP spec):
	// - Socket Address (16 bytes)
	// - Vendor ID (2 bytes)
	// - Product Type (2 bytes)
	// - Product Code (2 bytes)
	// - Revision (2 bytes, major.minor)
	// - Status (2 bytes)
	// - Serial Number (4 bytes)
	// - Product Name Length (1 byte)
	// - Product Name (variable)
	// - State (1 byte)

	if len(encap.Data) < 34 {
		return device, fmt.Errorf("ListIdentity data too short: %d bytes", len(encap.Data))
	}

	offset := 0

	// Skip Socket Address (16 bytes)
	offset += 16

	// Vendor ID (2 bytes, big-endian)
	device.VendorID = binary.BigEndian.Uint16(encap.Data[offset : offset+2])
	offset += 2

	// Product Type (2 bytes) - skip
	offset += 2

	// Product Code (2 bytes, big-endian)
	device.ProductID = binary.BigEndian.Uint16(encap.Data[offset : offset+2])
	offset += 2

	// Revision (2 bytes) - skip
	offset += 2

	// Status (2 bytes) - skip
	offset += 2

	// Serial Number (4 bytes, big-endian)
	device.SerialNumber = binary.BigEndian.Uint32(encap.Data[offset : offset+4])
	offset += 4

	// Product Name Length (1 byte)
	if offset >= len(encap.Data) {
		return device, fmt.Errorf("incomplete response at product name length")
	}
	nameLen := int(encap.Data[offset])
	offset++

	// Product Name (variable)
	if offset+nameLen > len(encap.Data) {
		return device, fmt.Errorf("incomplete product name")
	}
	if nameLen > 0 {
		device.ProductName = string(encap.Data[offset : offset+nameLen])
		offset += nameLen
	}

	// State (1 byte)
	if offset >= len(encap.Data) {
		return device, fmt.Errorf("incomplete response at state")
	}
	device.State = encap.Data[offset]

	return device, nil
}

