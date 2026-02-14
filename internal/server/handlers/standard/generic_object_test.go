package standard

import (
	"context"
	"testing"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
)

func TestGenericGetSetAttributeSingle(t *testing.T) {
	handler := NewGenericObjectHandler(map[uint16]struct{}{
		spec.CIPClassEnergyBase: {},
	})

	req := protocol.CIPRequest{
		Service: spec.CIPServiceSetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     0x00F6,
			Instance:  0x0001,
			Attribute: 0x0006,
		},
		Payload: []byte{0xDE, 0xAD},
	}
	resp, handled, err := handler.HandleCIPRequest(context.TODO(), req)
	if err != nil || !handled || resp.Status != 0x00 {
		t.Fatalf("expected set success, handled=%v status=0x%02X err=%v", handled, resp.Status, err)
	}

	readReq := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path:    req.Path,
	}
	readResp, handled, err := handler.HandleCIPRequest(context.TODO(), readReq)
	if err != nil || !handled || readResp.Status != 0x00 {
		t.Fatalf("expected read success, handled=%v status=0x%02X err=%v", handled, readResp.Status, err)
	}
	if len(readResp.Payload) != 2 || readResp.Payload[0] != 0xDE || readResp.Payload[1] != 0xAD {
		t.Fatalf("unexpected payload: %v", readResp.Payload)
	}
}

func TestGenericGetAttributeList(t *testing.T) {
	handler := NewGenericObjectHandler(nil)
	handler.store.set(0x0064, 0x0001, 0x0001, []byte{0x11})
	handler.store.set(0x0064, 0x0001, 0x0002, []byte{0x22, 0x33})

	req := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeList,
		Path: protocol.CIPPath{
			Class:    0x0064,
			Instance: 0x0001,
		},
		Payload: []byte{
			0x02, 0x00, // count
			0x01, 0x00, // attr 1
			0x02, 0x00, // attr 2
		},
	}
	resp, handled, err := handler.HandleCIPRequest(context.TODO(), req)
	if err != nil || !handled || resp.Status != 0x00 {
		t.Fatalf("expected list success, handled=%v status=0x%02X err=%v", handled, resp.Status, err)
	}
	if len(resp.Payload) == 0 {
		t.Fatalf("expected payload data")
	}
}

func TestEnergyMeteringServices(t *testing.T) {
	handler := NewGenericObjectHandler(map[uint16]struct{}{
		spec.CIPClassEnergyBase: {},
	})

	req := protocol.CIPRequest{
		Service: spec.CIPServiceExecutePCCC,
		Path: protocol.CIPPath{
			Class:    spec.CIPClassEnergyBase,
			Instance: 0x0001,
		},
	}
	resp, handled, err := handler.HandleCIPRequest(context.TODO(), req)
	if err != nil || !handled || resp.Status != 0x00 {
		t.Fatalf("expected start metering success, handled=%v status=0x%02X err=%v", handled, resp.Status, err)
	}

	req.Service = spec.CIPServiceReadTag
	resp, handled, err = handler.HandleCIPRequest(context.TODO(), req)
	if err != nil || !handled || resp.Status != 0x00 {
		t.Fatalf("expected stop metering success, handled=%v status=0x%02X err=%v", handled, resp.Status, err)
	}
}

func TestGenericProfileClassesBasicReadWrite(t *testing.T) {
	classes := []uint16{
		spec.CIPClassEventLog,
		spec.CIPClassTimeSync,
		spec.CIPClassModbus,
		spec.CIPClassMotionAxis,
		spec.CIPClassSafetySupervisor,
		spec.CIPClassSafetyValidator,
	}

	for _, classID := range classes {
		handler := NewGenericObjectHandler(map[uint16]struct{}{
			classID: {},
		})

		setReq := protocol.CIPRequest{
			Service: spec.CIPServiceSetAttributeSingle,
			Path: protocol.CIPPath{
				Class:     classID,
				Instance:  0x0001,
				Attribute: 0x0001,
			},
			Payload: []byte{0xAA},
		}
		resp, handled, err := handler.HandleCIPRequest(context.TODO(), setReq)
		if err != nil || !handled || resp.Status != 0x00 {
			t.Fatalf("class 0x%04X set failed: handled=%v status=0x%02X err=%v", classID, handled, resp.Status, err)
		}

		getReq := protocol.CIPRequest{
			Service: spec.CIPServiceGetAttributeSingle,
			Path:    setReq.Path,
		}
		resp, handled, err = handler.HandleCIPRequest(context.TODO(), getReq)
		if err != nil || !handled || resp.Status != 0x00 {
			t.Fatalf("class 0x%04X get failed: handled=%v status=0x%02X err=%v", classID, handled, resp.Status, err)
		}
		if len(resp.Payload) == 0 || resp.Payload[0] != 0xAA {
			t.Fatalf("class 0x%04X payload mismatch: %v", classID, resp.Payload)
		}
	}
}
