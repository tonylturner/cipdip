package server

import (
	"testing"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
)

func TestGenericGetSetAttributeSingle(t *testing.T) {
	cfg := &config.ServerConfig{}
	s := &Server{
		config:       cfg,
		genericStore: newGenericAttributeStore(),
		profileClasses: map[uint16]struct{}{
			cipclient.CIPClassEnergyBase: {},
		},
	}

	req := cipclient.CIPRequest{
		Service: cipclient.CIPServiceSetAttributeSingle,
		Path: cipclient.CIPPath{
			Class:     0x00F6,
			Instance:  0x0001,
			Attribute: 0x0006,
		},
		Payload: []byte{0xDE, 0xAD},
	}
	resp, ok := s.handleGenericRequest(req)
	if !ok || resp.Status != 0x00 {
		t.Fatalf("expected set success, ok=%v status=0x%02X", ok, resp.Status)
	}

	readReq := cipclient.CIPRequest{
		Service: cipclient.CIPServiceGetAttributeSingle,
		Path:    req.Path,
	}
	readResp, ok := s.handleGenericRequest(readReq)
	if !ok || readResp.Status != 0x00 {
		t.Fatalf("expected read success, ok=%v status=0x%02X", ok, readResp.Status)
	}
	if len(readResp.Payload) != 2 || readResp.Payload[0] != 0xDE || readResp.Payload[1] != 0xAD {
		t.Fatalf("unexpected payload: %v", readResp.Payload)
	}
}

func TestGenericGetAttributeList(t *testing.T) {
	cfg := &config.ServerConfig{}
	s := &Server{
		config:       cfg,
		genericStore: newGenericAttributeStore(),
	}
	s.genericStore.set(0x0064, 0x0001, 0x0001, []byte{0x11})
	s.genericStore.set(0x0064, 0x0001, 0x0002, []byte{0x22, 0x33})

	req := cipclient.CIPRequest{
		Service: cipclient.CIPServiceGetAttributeList,
		Path: cipclient.CIPPath{
			Class:    0x0064,
			Instance: 0x0001,
		},
		Payload: []byte{
			0x02, 0x00, // count
			0x01, 0x00, // attr 1
			0x02, 0x00, // attr 2
		},
	}
	resp, ok := s.handleGenericRequest(req)
	if !ok || resp.Status != 0x00 {
		t.Fatalf("expected list success, ok=%v status=0x%02X", ok, resp.Status)
	}
	if len(resp.Payload) == 0 {
		t.Fatalf("expected payload data")
	}
}

func TestEnergyMeteringServices(t *testing.T) {
	cfg := &config.ServerConfig{}
	s := &Server{
		config:       cfg,
		genericStore: newGenericAttributeStore(),
		profileClasses: map[uint16]struct{}{
			cipclient.CIPClassEnergyBase: {},
		},
	}

	req := cipclient.CIPRequest{
		Service: cipclient.CIPServiceExecutePCCC,
		Path: cipclient.CIPPath{
			Class:    cipclient.CIPClassEnergyBase,
			Instance: 0x0001,
		},
	}
	resp, ok := s.handleGenericRequest(req)
	if !ok || resp.Status != 0x00 {
		t.Fatalf("expected start metering success, ok=%v status=0x%02X", ok, resp.Status)
	}

	req.Service = cipclient.CIPServiceReadTag
	resp, ok = s.handleGenericRequest(req)
	if !ok || resp.Status != 0x00 {
		t.Fatalf("expected stop metering success, ok=%v status=0x%02X", ok, resp.Status)
	}
}

func TestGenericProfileClassesBasicReadWrite(t *testing.T) {
	classes := []uint16{
		cipclient.CIPClassEventLog,
		cipclient.CIPClassTimeSync,
		cipclient.CIPClassModbus,
		cipclient.CIPClassMotionAxis,
		cipclient.CIPClassSafetySupervisor,
		cipclient.CIPClassSafetyValidator,
	}

	for _, classID := range classes {
		s := &Server{
			config:       &config.ServerConfig{},
			genericStore: newGenericAttributeStore(),
			profileClasses: map[uint16]struct{}{
				classID: {},
			},
		}

		setReq := cipclient.CIPRequest{
			Service: cipclient.CIPServiceSetAttributeSingle,
			Path: cipclient.CIPPath{
				Class:     classID,
				Instance:  0x0001,
				Attribute: 0x0001,
			},
			Payload: []byte{0xAA},
		}
		resp, ok := s.handleGenericRequest(setReq)
		if !ok || resp.Status != 0x00 {
			t.Fatalf("class 0x%04X set failed: ok=%v status=0x%02X", classID, ok, resp.Status)
		}

		getReq := cipclient.CIPRequest{
			Service: cipclient.CIPServiceGetAttributeSingle,
			Path:    setReq.Path,
		}
		resp, ok = s.handleGenericRequest(getReq)
		if !ok || resp.Status != 0x00 {
			t.Fatalf("class 0x%04X get failed: ok=%v status=0x%02X", classID, ok, resp.Status)
		}
		if len(resp.Payload) == 0 || resp.Payload[0] != 0xAA {
			t.Fatalf("class 0x%04X payload mismatch: %v", classID, resp.Payload)
		}
	}
}
