package cipclient

import "testing"

func TestDecodeCIPRequestStrictPathSizeRequired(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prev)

	// Service only, missing path size.
	if _, err := DecodeCIPRequest([]byte{0x0E}); err == nil {
		t.Fatalf("expected missing path size error")
	}
}

func TestDecodeCIPRequestLegacyNoPathSize(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(LegacyCompatProfile)
	defer SetProtocolProfile(prev)

	data := []byte{
		0x0E,       // service
		0x20, 0x04, // class
		0x24, 0x01, // instance
		0x30, 0x01, // attribute
	}
	req, err := DecodeCIPRequest(data)
	if err != nil {
		t.Fatalf("DecodeCIPRequest error: %v", err)
	}
	if req.Path.Class != 0x04 || req.Path.Instance != 0x01 || req.Path.Attribute != 0x01 {
		t.Fatalf("unexpected path: %#v", req.Path)
	}
}

func TestDecodeCIPRequestStrictIncompletePath(t *testing.T) {
	prev := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prev)

	data := []byte{
		0x0E,
		0x02,       // path size words -> 4 bytes expected
		0x20, 0x04, // only 2 bytes provided
	}
	if _, err := DecodeCIPRequest(data); err == nil {
		t.Fatalf("expected incomplete EPATH error")
	}
}
