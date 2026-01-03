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
			Payload: []byte{0x01, 0x02},
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
