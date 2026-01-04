package cipclient

import "testing"

func TestValidateCIPRequestConnectionManagerServices(t *testing.T) {
	validator := NewPacketValidator(true)
	services := []CIPServiceCode{
		CIPServiceForwardOpen,
		CIPServiceForwardClose,
		CIPServiceGetConnectionData,
		CIPServiceSearchConnectionData,
		CIPServiceGetConnectionOwner,
		CIPServiceLargeForwardOpen,
	}

	for _, svc := range services {
		req := CIPRequest{
			Service: svc,
			Path: CIPPath{
				Class:    CIPClassConnectionManager,
				Instance: 0x0001,
			},
		}
		switch svc {
		case CIPServiceForwardOpen:
			payload, err := BuildForwardOpenPayload(ConnectionParams{
				Priority:              "scheduled",
				OToTRPIMs:             20,
				TToORPIMs:             20,
				OToTSizeBytes:         32,
				TToOSizeBytes:         32,
				TransportClassTrigger: 3,
				Class:                 CIPClassAssembly,
				Instance:              0x65,
			})
			if err != nil {
				t.Fatalf("BuildForwardOpenPayload error: %v", err)
			}
			req.Payload = payload
		case CIPServiceForwardClose:
			payload, err := BuildForwardClosePayload(0x11223344)
			if err != nil {
				t.Fatalf("BuildForwardClosePayload error: %v", err)
			}
			req.Payload = payload
		default:
			req.Payload = []byte{0x01, 0x02}
		}
		if err := validator.ValidateCIPRequest(req); err != nil {
			t.Fatalf("ValidateCIPRequest(%s) error: %v", svc, err)
		}
	}
}

func TestValidateCIPRequestFragmentedPayloads(t *testing.T) {
	validator := NewPacketValidator(true)

	readReq := CIPRequest{
		Service: CIPServiceReadTagFragmented,
		Path:    CIPPath{Class: 0x006B, Instance: 0x0001},
		Payload: nil,
	}
	if err := validator.ValidateCIPRequest(readReq); err == nil {
		t.Fatalf("expected error for missing Read_Tag_Fragmented payload")
	}

	readReq.Payload = []byte{0x01, 0x00, 0x00, 0x00}
	if err := validator.ValidateCIPRequest(readReq); err == nil {
		t.Fatalf("expected error for short Read_Tag_Fragmented payload")
	}

	readReq.Payload = BuildReadTagFragmentedPayload(1, 0)
	if err := validator.ValidateCIPRequest(readReq); err != nil {
		t.Fatalf("unexpected error for Read_Tag_Fragmented payload: %v", err)
	}

	writeReq := CIPRequest{
		Service: CIPServiceWriteTagFragmented,
		Path:    CIPPath{Class: 0x006B, Instance: 0x0001},
		Payload: []byte{0x00},
	}
	if err := validator.ValidateCIPRequest(writeReq); err == nil {
		t.Fatalf("expected error for short Write_Tag_Fragmented payload")
	}

	writeReq.Payload = BuildWriteTagFragmentedPayload(uint16(CIPTypeDINT), 1, 0, []byte{0x01, 0x02, 0x03, 0x04})
	if err := validator.ValidateCIPRequest(writeReq); err != nil {
		t.Fatalf("unexpected error for Write_Tag_Fragmented payload: %v", err)
	}
}

func TestValidateCIPRequestUnconnectedSendEmbedded(t *testing.T) {
	validator := NewPacketValidator(true)
	embedded := CIPRequest{
		Service: CIPServiceGetAttributeSingle,
		Path: CIPPath{
			Class:    CIPClassIdentityObject,
			Instance: 0x01,
		},
	}
	embeddedBytes, err := EncodeCIPRequest(embedded)
	if err != nil {
		t.Fatalf("EncodeCIPRequest error: %v", err)
	}
	payload, err := BuildUnconnectedSendPayload(embeddedBytes, UnconnectedSendOptions{})
	if err != nil {
		t.Fatalf("BuildUnconnectedSendPayload error: %v", err)
	}
	req := CIPRequest{
		Service: CIPServiceUnconnectedSend,
		Path: CIPPath{
			Class:    CIPClassConnectionManager,
			Instance: 0x0001,
		},
		Payload: payload,
	}
	if err := validator.ValidateCIPRequest(req); err != nil {
		t.Fatalf("ValidateCIPRequest(Unconnected_Send) error: %v", err)
	}
}
