package cipclient

import (
	"strings"
	"testing"
)

func TestReferencePacketsServicePathRegression(t *testing.T) {
	prevProfile := CurrentProtocolProfile()
	SetProtocolProfile(StrictODVAProfile)
	defer SetProtocolProfile(prevProfile)

	for key, ref := range ReferencePackets {
		if len(ref.Data) == 0 {
			continue
		}

		encap, err := DecodeENIP(ref.Data)
		if err != nil {
			t.Fatalf("%s: decode ENIP: %v", key, err)
		}

		if encap.Command != ENIPCommandSendRRData {
			continue
		}

		cipData, err := ParseSendRRDataRequest(encap.Data)
		if err != nil {
			t.Fatalf("%s: parse SendRRData: %v", key, err)
		}
		if len(cipData) == 0 {
			continue
		}

		if len(ref.Description) > 0 && !strings.Contains(ref.Description, "Request") {
			continue
		}

		req, err := DecodeCIPRequest(cipData)
		if err != nil {
			t.Fatalf("%s: decode CIP request: %v", key, err)
		}

		label, known := labelCIPService(uint8(req.Service), req.Path, false)
		if !known {
			t.Fatalf("%s: unsupported service/path label=%s", key, label)
		}

		if req.Path.Class == 0 && req.Path.Instance == 0 && req.Path.Attribute == 0 && req.Path.Name == "" {
			t.Fatalf("%s: missing CIP path in reference request", key)
		}
	}
}
