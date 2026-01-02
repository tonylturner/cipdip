package cipclient

import "testing"

func TestParseUnconnectedSendRequest(t *testing.T) {
	embedded := []byte{
		0x4C, 0x02, 0x20, 0x6B, 0x24, 0x01,
	}
	cip := []byte{
		0x52, 0x02, 0x20, 0x06, 0x24, 0x01,
		0x0A, 0x0E, 0x06, 0x00,
	}
	cip = append(cip, embedded...)
	cip = append(cip, 0x00, 0x00)

	info, err := parseCIPMessage(cip)
	if err != nil {
		t.Fatalf("parseCIPMessage failed: %v", err)
	}
	if info.BaseService != 0x52 {
		t.Fatalf("Expected service 0x52, got 0x%02X", info.BaseService)
	}
	if info.PathInfo.Path.Class != 0x06 || info.PathInfo.Path.Instance != 0x01 {
		t.Fatalf("Unexpected path: class=0x%04X instance=0x%04X", info.PathInfo.Path.Class, info.PathInfo.Path.Instance)
	}
	embeddedData, ok := parseUnconnectedSendRequest(cip[info.DataOffset:])
	if !ok {
		t.Fatalf("parseUnconnectedSendRequest failed")
	}
	embeddedInfo, err := parseCIPMessage(embeddedData)
	if err != nil {
		t.Fatalf("parseCIPMessage (embedded) failed: %v", err)
	}
	if embeddedInfo.BaseService != 0x4C {
		t.Fatalf("Expected embedded service 0x4C, got 0x%02X", embeddedInfo.BaseService)
	}
	if embeddedInfo.PathInfo.Path.Class != 0x006B {
		t.Fatalf("Unexpected embedded class: 0x%04X", embeddedInfo.PathInfo.Path.Class)
	}
}
