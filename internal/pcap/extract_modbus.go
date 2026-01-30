package pcap

// Modbus PCAP extraction: extract Modbus TCP (MBAP) frames from port 502 traffic.

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/tturner/cipdip/internal/modbus"
)

// ModbusPacket represents an extracted Modbus frame from a PCAP.
type ModbusPacket struct {
	TransactionID uint16              // MBAP transaction ID
	UnitID        uint8               // Modbus unit/slave address
	Function      modbus.FunctionCode // Function code
	Data          []byte              // PDU data (after function code)
	FullFrame     []byte              // Complete MBAP + PDU
	IsRequest     bool                // Direction: true = client→server
	IsException   bool                // True if response indicates exception
	Description   string              // Human-readable description
	Timestamp     time.Time           // Capture timestamp
	Transport     string              // "tcp" or "udp"
	Mode          modbus.TransportMode // Detected transport mode
	SrcIP         string
	DstIP         string
	SrcPort       uint16
	DstPort       uint16
}

// ModbusPort is the standard Modbus TCP port.
const ModbusPort = 502

// ExtractModbusFromPCAP extracts Modbus frames from a PCAP file.
// Supports Modbus TCP (MBAP) on port 502 with TCP stream reassembly.
func ExtractModbusFromPCAP(pcapFile string) ([]ModbusPacket, error) {
	handle, err := pcap.OpenOffline(pcapFile)
	if err != nil {
		return nil, fmt.Errorf("open pcap file: %w", err)
	}
	defer handle.Close()

	var packets []ModbusPacket
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	streams := make(map[string][]byte)

	for packet := range packetSource.Packets() {
		meta := extractPacketMeta(packet)

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			if !isModbusPort(uint16(tcp.SrcPort), uint16(tcp.DstPort)) {
				continue
			}
			if len(tcp.Payload) == 0 {
				continue
			}

			netLayer := packet.NetworkLayer()
			key := streamKey(netLayer, tcp)
			streams[key] = append(streams[key], tcp.Payload...)
			streamBuf := streams[key]

			isToServer := tcp.DstPort == ModbusPort

			if meta != nil {
				meta.Transport = "tcp"
				meta.SrcPort = uint16(tcp.SrcPort)
				meta.DstPort = uint16(tcp.DstPort)
			}

			parsed, remaining := extractModbusFrames(streamBuf, isToServer, meta)
			packets = append(packets, parsed...)
			streams[key] = remaining
		}

		// Modbus UDP is rare but technically valid per the spec.
		udpLayer := packet.Layer(layers.LayerTypeUDP)
		if udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			if !isModbusPort(uint16(udp.SrcPort), uint16(udp.DstPort)) {
				continue
			}
			if len(udp.Payload) == 0 {
				continue
			}

			isToServer := udp.DstPort == ModbusPort
			if meta != nil {
				meta.Transport = "udp"
				meta.SrcPort = uint16(udp.SrcPort)
				meta.DstPort = uint16(udp.DstPort)
			}

			parsed, _ := extractModbusFrames(udp.Payload, isToServer, meta)
			packets = append(packets, parsed...)
		}
	}

	return packets, nil
}

// extractModbusFrames extracts complete Modbus TCP (MBAP) frames from a byte buffer.
// Returns extracted packets and any remaining incomplete bytes.
func extractModbusFrames(payload []byte, isToServer bool, meta *ENIPMetadata) ([]ModbusPacket, []byte) {
	var packets []ModbusPacket

	for len(payload) >= modbus.MBAPHeaderSize+1 { // header + at least FC byte
		hdr, err := modbus.DecodeMBAPHeader(payload)
		if err != nil {
			// Can't parse header - discard one byte and try again.
			payload = payload[1:]
			continue
		}

		// Validate protocol ID
		if hdr.ProtocolID != 0x0000 {
			payload = payload[1:]
			continue
		}

		// Validate length: must be >= 2 (unit + FC) and plausible
		if hdr.Length < 2 || hdr.Length > modbus.MaxPDUSize+1 {
			payload = payload[1:]
			continue
		}

		frameLen := modbus.MBAPHeaderSize + int(hdr.Length) - 1 // -1 because UnitID is in header but counted in Length
		if frameLen > len(payload) {
			// Incomplete frame - wait for more data.
			break
		}

		// Extract the full frame
		fullFrame := make([]byte, frameLen)
		copy(fullFrame, payload[:frameLen])

		fc := modbus.FunctionCode(payload[modbus.MBAPHeaderSize])
		pduData := make([]byte, frameLen-modbus.MBAPHeaderSize-1)
		if len(pduData) > 0 {
			copy(pduData, payload[modbus.MBAPHeaderSize+1:frameLen])
		}

		isException := fc&0x80 != 0
		pkt := ModbusPacket{
			TransactionID: hdr.TransactionID,
			UnitID:        hdr.UnitID,
			Function:      fc,
			Data:          pduData,
			FullFrame:     fullFrame,
			IsRequest:     isToServer,
			IsException:   isException,
			Description:   describeModbusFrame(fc, isToServer, isException, pduData),
			Mode:          modbus.ModeTCP,
			Timestamp:     metadataValue(meta, func(m *ENIPMetadata) time.Time { return m.Timestamp }),
			Transport:     metadataValue(meta, func(m *ENIPMetadata) string { return m.Transport }),
			SrcIP:         metadataValue(meta, func(m *ENIPMetadata) string { return m.SrcIP }),
			DstIP:         metadataValue(meta, func(m *ENIPMetadata) string { return m.DstIP }),
			SrcPort:       metadataValue(meta, func(m *ENIPMetadata) uint16 { return m.SrcPort }),
			DstPort:       metadataValue(meta, func(m *ENIPMetadata) uint16 { return m.DstPort }),
		}
		packets = append(packets, pkt)
		payload = payload[frameLen:]
	}

	// Return remaining bytes
	if len(payload) == 0 {
		return packets, nil
	}
	remaining := make([]byte, len(payload))
	copy(remaining, payload)
	return packets, remaining
}

func isModbusPort(src, dst uint16) bool {
	return src == ModbusPort || dst == ModbusPort
}

func describeModbusFrame(fc modbus.FunctionCode, isRequest, isException bool, data []byte) string {
	dir := "Request"
	if !isRequest {
		dir = "Response"
	}

	if isException {
		baseFc := fc & 0x7F
		exc := "unknown"
		if len(data) > 0 {
			exc = modbus.ExceptionCode(data[0]).String()
		}
		return fmt.Sprintf("Modbus %s Exception: %s (%s)",
			modbus.FunctionCode(baseFc).String(), exc, dir)
	}

	return fmt.Sprintf("Modbus %s %s", fc.String(), dir)
}
