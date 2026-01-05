package spec

import (
	"testing"

	"github.com/tturner/cipdip/internal/cip/protocol"
)

func TestLabelServiceContextual(t *testing.T) {
	cases := []struct {
		service uint8
		path    protocol.CIPPath
		resp    bool
		want    string
	}{
		{0x52, protocol.CIPPath{Class: CIPClassConnectionManager, Instance: 0x0001}, false, "Unconnected_Send"},
		{0x52, protocol.CIPPath{Class: 0x006B, Instance: 0x0001}, false, "Read_Tag_Fragmented"},
		{0x4E, protocol.CIPPath{Class: CIPClassConnectionManager, Instance: 0x0001}, false, "Forward_Close"},
		{0x4B, protocol.CIPPath{Class: 0x0037, Instance: 0x0001}, false, "Initiate_Upload"},
		{0x4B, protocol.CIPPath{Class: 0x0067, Instance: 0x0001}, false, "Execute_PCCC"},
		{0x54, protocol.CIPPath{Class: CIPClassConnectionManager, Instance: 0x0001}, false, "Forward_Open"},
		{0x4C, protocol.CIPPath{Class: 0x006C, Instance: 0x0001}, false, "Template_Read"},
		{0x4D, protocol.CIPPath{Class: 0x0037, Instance: 0x0001}, false, "Initiate_Partial_Read"},
		{0x52, protocol.CIPPath{Class: CIPClassConnectionManager, Instance: 0x0001}, true, "Unconnected_Send_Response"},
	}

	for _, tc := range cases {
		name, ok := LabelService(tc.service, tc.path, tc.resp)
		if !ok {
			t.Fatalf("expected label for service 0x%02X", tc.service)
		}
		if name != tc.want {
			t.Fatalf("label mismatch for service 0x%02X: got %s want %s", tc.service, name, tc.want)
		}
	}
}
