package validation

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// BytesPacket carries an ENIP packet with its validation expectation.
type BytesPacket struct {
	Expect  PacketExpectation `json:"expect"`
	ENIPHex string            `json:"enip_hex"`
}

// BytesOutput is emitted by cipclient byte generation mode.
type BytesOutput struct {
	GeneratedAt string        `json:"generated_at"`
	Packets     []BytesPacket `json:"packets"`
}

// DecodeHexBytes decodes a hex string into raw bytes.
func DecodeHexBytes(input string) ([]byte, error) {
	cleaned := strings.TrimSpace(input)
	cleaned = strings.TrimPrefix(cleaned, "0x")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	if cleaned == "" {
		return nil, nil
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("hex payload must have even length")
	}
	decoded := make([]byte, len(cleaned)/2)
	if _, err := hex.Decode(decoded, []byte(cleaned)); err != nil {
		return nil, err
	}
	return decoded, nil
}

// NewBytesOutput initializes a BytesOutput with timestamp.
func NewBytesOutput() BytesOutput {
	return BytesOutput{GeneratedAt: time.Now().UTC().Format(time.RFC3339)}
}
