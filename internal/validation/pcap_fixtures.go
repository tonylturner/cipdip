package validation

import (
	"fmt"
	"github.com/tturner/cipdip/internal/cip/spec"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/enip"
)

type ValidationRequestSpec struct {
	Name            string
	Req             protocol.CIPRequest
	PayloadType     string
	PayloadParams   map[string]any
	ServiceShape    string
	IncludeResponse bool
	ExpectSymbol    bool
	Outcome         string
	ResponseOutcome string
	TrafficMode     string
}

type ValidationPCAPSpec struct {
	Name     string
	Requests []ValidationRequestSpec
}

type ValidationPacket struct {
	Data   []byte
	Expect PacketExpectation
}

func DefaultValidationPCAPSpecs() ([]ValidationPCAPSpec, error) {
	embeddedReq := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     spec.CIPClassIdentityObject,
			Instance:  0x01,
			Attribute: 0x01,
		},
	}
	embeddedBytes, err := protocol.EncodeCIPRequest(embeddedReq)
	if err != nil {
		return nil, fmt.Errorf("encode embedded request: %w", err)
	}

	cases := []ValidationPCAPSpec{
		{
			Name: "common_services",
			Requests: append(commonServiceRequests(), ValidationRequestSpec{
				Name:            "multiple_service_packet",
				Req:             buildMultipleServiceRequest(),
				ServiceShape:    ServiceShapePayload,
				IncludeResponse: true,
			}),
		},
		{
			Name: "core",
			Requests: []ValidationRequestSpec{
				{
					Name: "get_attribute_single",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceGetAttributeSingle,
						Path: protocol.CIPPath{
							Class:     spec.CIPClassIdentityObject,
							Instance:  0x01,
							Attribute: 0x01,
						},
					},
					ServiceShape:    ServiceShapeNone,
					IncludeResponse: true,
				},
				{
					Name: "set_attribute_single",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceSetAttributeSingle,
						Path: protocol.CIPPath{
							Class:     spec.CIPClassAssembly,
							Instance:  0x64,
							Attribute: 0x03,
						},
						Payload: []byte{0x01, 0x00},
					},
					ServiceShape:    ServiceShapeWrite,
					IncludeResponse: true,
				},
				{
					Name: "forward_open",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceForwardOpen,
						Path:    protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadForwardOpen),
					PayloadParams: map[string]any{
						"connection_class":    uint64(spec.CIPClassAssembly),
						"connection_instance": uint64(0x65),
					},
					ServiceShape:    ServiceShapeForwardOpen,
					IncludeResponse: true,
					Outcome:         "invalid",
					ResponseOutcome: "invalid",
				},
				{
					Name: "forward_close",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceForwardClose,
						Path:    protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadForwardClose),
					PayloadParams: map[string]any{
						"connection_id": uint64(0x11223344),
					},
					ServiceShape:    ServiceShapeForwardClose,
					IncludeResponse: true,
					Outcome:         "invalid",
					ResponseOutcome: "valid",
				},
				{
					Name: "unconnected_send",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceUnconnectedSend,
						Path:    protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadUnconnectedSend),
					PayloadParams: map[string]any{
						"embedded_request_hex": embeddedBytes,
						"route_slot":           uint64(1),
					},
					ServiceShape:    ServiceShapeUnconnectedSend,
					IncludeResponse: true,
				},
			},
		},
		{
			Name: "rockwell",
			Requests: []ValidationRequestSpec{
				{
					Name: "read_tag",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceReadTag,
						Path:    protocol.CIPPath{Class: spec.CIPClassSymbolObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTag),
					PayloadParams: map[string]any{
						"tag": "TestTag",
					},
					ServiceShape:    ServiceShapeRockwellTag,
					ExpectSymbol:    true,
					IncludeResponse: true,
				},
				{
					Name: "write_tag",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceWriteTag,
						Path:    protocol.CIPPath{Class: spec.CIPClassSymbolObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTag),
					PayloadParams: map[string]any{
						"tag":   "TestTag",
						"type":  "DINT",
						"value": "123",
					},
					ServiceShape:    ServiceShapeRockwellTag,
					ExpectSymbol:    true,
					IncludeResponse: true,
				},
				{
					Name: "read_tag_fragmented",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceReadTagFragmented,
						Path:    protocol.CIPPath{Class: spec.CIPClassSymbolObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTagFrag),
					PayloadParams: map[string]any{
						"tag":    "TestTag",
						"offset": uint64(0),
					},
					ServiceShape:    ServiceShapeRockwellTagFrag,
					ExpectSymbol:    true,
					IncludeResponse: true,
				},
				{
					Name: "write_tag_fragmented",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceWriteTagFragmented,
						Path:    protocol.CIPPath{Class: spec.CIPClassSymbolObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTagFrag),
					PayloadParams: map[string]any{
						"tag":    "TestTag",
						"type":   "DINT",
						"value":  "456",
						"offset": uint64(0),
					},
					ServiceShape:    ServiceShapeRockwellTagFrag,
					ExpectSymbol:    true,
					IncludeResponse: true,
				},
				{
					Name: "execute_pccc",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceExecutePCCC,
						Path:    protocol.CIPPath{Class: spec.CIPClassPCCCObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellPCCC),
					PayloadParams: map[string]any{
						"pccc_hex": "0f0000000000",
					},
					ServiceShape:    ServiceShapePCCC,
					IncludeResponse: true,
					Outcome:         "invalid",
					ResponseOutcome: "invalid",
				},
				{
					Name: "template_read",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceReadTag,
						Path:    protocol.CIPPath{Class: spec.CIPClassTemplateObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTemplate),
					PayloadParams: map[string]any{
						"offset": uint64(0),
						"length": uint64(64),
					},
					ServiceShape:    ServiceShapeTemplate,
					IncludeResponse: true,
				},
			},
		},
		{
			Name: "file_modbus",
			Requests: []ValidationRequestSpec{
				{
					Name: "file_initiate_upload",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceInitiateUpload,
						Path:    protocol.CIPPath{Class: spec.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"file_size": uint64(1024),
					},
					ServiceShape:    ServiceShapeFileObject,
					IncludeResponse: true,
					ResponseOutcome: "invalid",
				},
				{
					Name: "file_initiate_download",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceInitiateDownload,
						Path:    protocol.CIPPath{Class: spec.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"file_size":      uint64(512),
						"format_version": uint64(1),
						"file_revision":  uint64(1),
						"file_name":      "test.bin",
					},
					ServiceShape:    ServiceShapeFileObject,
					IncludeResponse: true,
					ResponseOutcome: "invalid",
				},
				{
					Name: "file_partial_read",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceInitiatePartialRead,
						Path:    protocol.CIPPath{Class: spec.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"file_offset": uint64(0),
						"chunk":       uint64(32),
					},
					ServiceShape:    ServiceShapeFileObject,
					IncludeResponse: true,
				},
				{
					Name: "file_partial_write",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceInitiatePartialWrite,
						Path:    protocol.CIPPath{Class: spec.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"file_offset": uint64(0),
						"data_hex":    "01020304",
					},
					ServiceShape:    ServiceShapeFileObject,
					IncludeResponse: true,
				},
				{
					Name: "file_upload_transfer",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceUploadTransfer,
						Path:    protocol.CIPPath{Class: spec.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"transfer_number": uint64(1),
					},
					ServiceShape:    ServiceShapeFileObject,
					IncludeResponse: true,
					ResponseOutcome: "invalid",
				},
				{
					Name: "file_download_transfer",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceDownloadTransfer,
						Path:    protocol.CIPPath{Class: spec.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"transfer_number": uint64(1),
						"transfer_type":   uint64(1),
						"data_hex":        "0102",
					},
					ServiceShape:    ServiceShapeFileObject,
					IncludeResponse: true,
				},
				{
					Name: "file_clear",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceClearFile,
						Path:    protocol.CIPPath{Class: spec.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType:     string(cipclient.PayloadFileObject),
					ServiceShape:    ServiceShapeNone,
					IncludeResponse: true,
				},
				{
					Name: "modbus_read_discrete_inputs",
					Req: protocol.CIPRequest{
						Service: 0x4B,
						Path:    protocol.CIPPath{Class: spec.CIPClassModbus, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadModbusObject),
					PayloadParams: map[string]any{
						"modbus_addr": uint64(0),
						"modbus_qty":  uint64(2),
					},
					ServiceShape:    ServiceShapeModbus,
					IncludeResponse: true,
				},
				{
					Name: "modbus_write_holding_registers",
					Req: protocol.CIPRequest{
						Service: 0x50,
						Path:    protocol.CIPPath{Class: spec.CIPClassModbus, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadModbusObject),
					PayloadParams: map[string]any{
						"modbus_addr":     uint64(1),
						"modbus_qty":      uint64(1),
						"modbus_data_hex": "0001",
					},
					ServiceShape:    ServiceShapeModbus,
					IncludeResponse: true,
					ResponseOutcome: "invalid",
				},
				{
					Name: "modbus_passthrough",
					Req: protocol.CIPRequest{
						Service: 0x51,
						Path:    protocol.CIPPath{Class: spec.CIPClassModbus, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadModbusObject),
					PayloadParams: map[string]any{
						"modbus_pdu_hex": "030000000001",
					},
					ServiceShape:    ServiceShapeModbus,
					IncludeResponse: true,
				},
			},
		},
		{
			Name: "safety_energy_motion",
			Requests: []ValidationRequestSpec{
				{
					Name: "safety_reset",
					Req: protocol.CIPRequest{
						Service: 0x54,
						Path:    protocol.CIPPath{Class: spec.CIPClassSafetySupervisor, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadSafetyReset),
					PayloadParams: map[string]any{
						"reset_type": uint64(0),
					},
					ServiceShape:    ServiceShapeSafetyReset,
					IncludeResponse: true,
				},
				{
					Name: "energy_start_metering",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceExecutePCCC,
						Path:    protocol.CIPPath{Class: spec.CIPClassEnergyBase, Instance: 0x01},
						Payload: []byte{0x00},
					},
					ServiceShape:    ServiceShapePayload,
					IncludeResponse: true,
				},
				{
					Name: "motion_axis_list",
					Req: protocol.CIPRequest{
						Service: spec.CIPServiceExecutePCCC,
						Path:    protocol.CIPPath{Class: spec.CIPClassMotionAxis, Instance: 0x01},
						Payload: []byte{0x00},
					},
					ServiceShape:    ServiceShapePayload,
					IncludeResponse: true,
				},
			},
		},
	}

	return cases, nil
}

func commonServiceRequests() []ValidationRequestSpec {
	path := protocol.CIPPath{
		Class:     spec.CIPClassIdentityObject,
		Instance:  0x01,
		Attribute: 0x01,
	}
	assemblyPath := protocol.CIPPath{
		Class:     spec.CIPClassAssembly,
		Instance:  0x65,
		Attribute: 0x03,
	}
	attrList := buildAttributeListPayload([]uint16{0x01})
	setAttrList := buildSetAttributeListPayload([]uint16{0x01}, [][]byte{{0x01, 0x00}})

	return []ValidationRequestSpec{
		{Name: "get_attribute_all", Req: protocol.CIPRequest{Service: spec.CIPServiceGetAttributeAll, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "set_attribute_all", Req: protocol.CIPRequest{Service: spec.CIPServiceSetAttributeAll, Path: assemblyPath, Payload: []byte{0x00}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "get_attribute_list", Req: protocol.CIPRequest{Service: spec.CIPServiceGetAttributeList, Path: path, Payload: attrList}, ServiceShape: ServiceShapeRead, IncludeResponse: true},
		{Name: "set_attribute_list", Req: protocol.CIPRequest{Service: spec.CIPServiceSetAttributeList, Path: assemblyPath, Payload: setAttrList}, ServiceShape: ServiceShapeWrite, IncludeResponse: false},
		{Name: "reset", Req: protocol.CIPRequest{Service: spec.CIPServiceReset, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "start", Req: protocol.CIPRequest{Service: spec.CIPServiceStart, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "stop", Req: protocol.CIPRequest{Service: spec.CIPServiceStop, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "create", Req: protocol.CIPRequest{Service: spec.CIPServiceCreate, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true, ResponseOutcome: "invalid"},
		{Name: "delete", Req: protocol.CIPRequest{Service: spec.CIPServiceDelete, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "apply_attributes", Req: protocol.CIPRequest{Service: spec.CIPServiceApplyAttributes, Path: assemblyPath}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_attribute_single", Req: protocol.CIPRequest{Service: spec.CIPServiceGetAttributeSingle, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "set_attribute_single", Req: protocol.CIPRequest{Service: spec.CIPServiceSetAttributeSingle, Path: assemblyPath, Payload: []byte{0x01, 0x00}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "find_next_object_instance", Req: protocol.CIPRequest{Service: spec.CIPServiceFindNextObjectInst, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true, Outcome: "invalid", ResponseOutcome: "invalid"},
		{Name: "restore", Req: protocol.CIPRequest{Service: spec.CIPServiceRestore, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "save", Req: protocol.CIPRequest{Service: spec.CIPServiceSave, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "nop", Req: protocol.CIPRequest{Service: spec.CIPServiceNoOp, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_member", Req: protocol.CIPRequest{Service: spec.CIPServiceGetMember, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "set_member", Req: protocol.CIPRequest{Service: spec.CIPServiceSetMember, Path: path, Payload: []byte{0x00, 0x01}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "insert_member", Req: protocol.CIPRequest{Service: spec.CIPServiceInsertMember, Path: path, Payload: []byte{0x00, 0x01}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "remove_member", Req: protocol.CIPRequest{Service: spec.CIPServiceRemoveMember, Path: path, Payload: []byte{0x00, 0x01}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "group_sync", Req: protocol.CIPRequest{Service: spec.CIPServiceGroupSync, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: false},
		{Name: "get_instance_attribute_list", Req: protocol.CIPRequest{Service: spec.CIPServiceGetInstanceAttrList, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_connection_data", Req: protocol.CIPRequest{Service: spec.CIPServiceGetConnectionData, Path: protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 0x01}}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "search_connection_data", Req: protocol.CIPRequest{Service: spec.CIPServiceSearchConnectionData, Path: protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 0x01}}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_connection_owner", Req: protocol.CIPRequest{Service: spec.CIPServiceGetConnectionOwner, Path: protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 0x01}}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "large_forward_open", Req: protocol.CIPRequest{Service: spec.CIPServiceLargeForwardOpen, Path: protocol.CIPPath{Class: spec.CIPClassConnectionManager, Instance: 0x01}, Payload: []byte{0x00}}, ServiceShape: ServiceShapePayload, IncludeResponse: false, Outcome: "invalid"},
		{Name: "read_modify_write", Req: protocol.CIPRequest{Service: spec.CIPServiceReadModifyWrite, Path: assemblyPath, Payload: []byte{0x00}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
	}
}

func buildMultipleServiceRequest() protocol.CIPRequest {
	req1 := protocol.CIPRequest{
		Service: spec.CIPServiceGetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     spec.CIPClassIdentityObject,
			Instance:  0x01,
			Attribute: 0x01,
		},
	}
	req2 := protocol.CIPRequest{
		Service: spec.CIPServiceSetAttributeSingle,
		Path: protocol.CIPPath{
			Class:     spec.CIPClassAssembly,
			Instance:  0x65,
			Attribute: 0x03,
		},
		Payload: []byte{0x01, 0x00},
	}
	request, err := cipclient.BuildMultipleServiceRequest([]protocol.CIPRequest{req1, req2})
	if err != nil {
		return protocol.CIPRequest{
			Service: spec.CIPServiceMultipleService,
			Path: protocol.CIPPath{
				Class:    spec.CIPClassMessageRouter,
				Instance: 0x01,
			},
			Payload: []byte{},
		}
	}
	return request
}

func buildAttributeListPayload(attrs []uint16) []byte {
	order := cipclient.CurrentProtocolProfile().CIPByteOrder
	buf := make([]byte, 2+len(attrs)*2)
	codec.PutUint16(order, buf[:2], uint16(len(attrs)))
	offset := 2
	for _, attr := range attrs {
		codec.PutUint16(order, buf[offset:offset+2], attr)
		offset += 2
	}
	return buf
}

func buildSetAttributeListPayload(attrs []uint16, values [][]byte) []byte {
	order := cipclient.CurrentProtocolProfile().CIPByteOrder
	if len(attrs) == 0 {
		return []byte{0x00, 0x00}
	}
	buf := make([]byte, 2)
	codec.PutUint16(order, buf[:2], uint16(len(attrs)))
	for i, attr := range attrs {
		buf = codec.AppendUint16(order, buf, attr)
		if i < len(values) && len(values[i]) > 0 {
			buf = append(buf, values[i]...)
		} else {
			buf = append(buf, 0x00)
		}
	}
	return buf
}

// append helpers moved to internal/cip/codec

func buildPacketExpectation(reqSpec ValidationRequestSpec, direction string) PacketExpectation {
	outcome := strings.TrimSpace(reqSpec.Outcome)
	if direction == "response" {
		outcome = strings.TrimSpace(reqSpec.ResponseOutcome)
		if outcome == "" {
			outcome = strings.TrimSpace(reqSpec.Outcome)
		}
	}
	if outcome == "" {
		outcome = "valid"
	}
	trafficMode := strings.TrimSpace(reqSpec.TrafficMode)
	if trafficMode == "" {
		trafficMode = "client_only"
	}
	expect := PacketExpectation{
		ID:           fmt.Sprintf("%s/%s", reqSpec.Name, direction),
		Outcome:      outcome,
		Direction:    direction,
		PacketType:   "explicit_request",
		ServiceShape: reqSpec.ServiceShape,
		TrafficMode:  trafficMode,
		ExpectLayers: []string{"eth", "ip", "tcp", "enip", "cip"},
		ExpectENIP:   true,
		ExpectCPF:    true,
		ExpectCIP:    true,
	}

	if direction == "response" {
		expect.PacketType = "explicit_response"
		expect.ExpectStatus = true
		expect.ExpectCIPPath = false
		expect.ExpectSymbol = false
		return expect
	}

	if reqSpec.ExpectSymbol {
		expect.ExpectSymbol = true
		expect.ExpectCIPPath = false
	} else {
		expect.ExpectCIPPath = true
	}

	return expect
}

func buildResponseForRequest(req protocol.CIPRequest, reqSpec ValidationRequestSpec) (*protocol.CIPResponse, error) {
	resp := &protocol.CIPResponse{
		Service: responseServiceCode(req.Service),
		Status:  0x00,
		Path:    req.Path,
	}

	if req.Service == spec.CIPServiceMultipleService {
		payload, err := buildMultipleServiceResponsePayload(req)
		if err != nil {
			return nil, err
		}
		resp.Payload = payload
		return resp, nil
	}
	if req.Service == spec.CIPServiceGetAttributeSingle || req.Service == spec.CIPServiceGetAttributeAll || req.Service == spec.CIPServiceGetAttributeList {
		resp.Payload = defaultResponsePayload(ServiceShapeRead)
		return resp, nil
	}

	switch reqSpec.ServiceShape {
	case ServiceShapeForwardOpen:
		resp.Payload = make([]byte, 17)
		return resp, nil
	case ServiceShapeUnconnectedSend:
		embedded, _, ok := protocol.ParseUnconnectedSendRequestPayload(req.Payload)
		if !ok || len(embedded) == 0 {
			return nil, fmt.Errorf("unconnected_send missing embedded request")
		}
		embeddedReq, err := protocol.DecodeCIPRequest(embedded)
		if err != nil {
			return nil, fmt.Errorf("decode embedded request: %w", err)
		}
		embeddedResp := protocol.CIPResponse{
			Service: responseServiceCode(embeddedReq.Service),
			Status:  0x00,
			Path:    embeddedReq.Path,
			Payload: defaultResponsePayload(ServiceShapeRead),
		}
		embeddedData, err := protocol.EncodeCIPResponse(embeddedResp)
		if err != nil {
			return nil, fmt.Errorf("encode embedded response: %w", err)
		}
		resp.Payload = cipclient.BuildUnconnectedSendResponsePayload(embeddedData)
		return resp, nil
	case ServiceShapePayload:
		resp.Payload = []byte{0x00}
		return resp, nil
	case ServiceShapeRead:
		resp.Payload = defaultResponsePayload(ServiceShapeRead)
		return resp, nil
	case ServiceShapeWrite:
		return resp, nil
	case ServiceShapeFragmented, ServiceShapeRockwellTag, ServiceShapeRockwellTagFrag, ServiceShapeTemplate, ServiceShapePCCC, ServiceShapeFileObject, ServiceShapeModbus, ServiceShapeSafetyReset:
		resp.Payload = defaultResponsePayload(reqSpec.ServiceShape)
		return resp, nil
	}

	return resp, nil
}

func buildMultipleServiceResponsePayload(req protocol.CIPRequest) ([]byte, error) {
	requests, err := cipclient.ParseMultipleServiceRequestPayload(req.Payload)
	if err != nil {
		return nil, fmt.Errorf("parse multiple service payload: %w", err)
	}
	responses := make([]protocol.CIPResponse, 0, len(requests))
	for _, embedded := range requests {
		resp := protocol.CIPResponse{
			Service: responseServiceCode(embedded.Service),
			Status:  0x00,
			Path:    embedded.Path,
		}
		resp.Payload = defaultResponsePayload(ServiceShapeRead)
		responses = append(responses, resp)
	}
	return cipclient.BuildMultipleServiceResponsePayload(responses)
}

func responseServiceCode(service protocol.CIPServiceCode) protocol.CIPServiceCode {
	return protocol.CIPServiceCode(uint8(service) | 0x80)
}

func defaultResponsePayload(shape string) []byte {
	switch shape {
	case ServiceShapeRead, ServiceShapeRockwellTag, ServiceShapeRockwellTagFrag:
		return []byte{0x00, 0x00}
	case ServiceShapeTemplate:
		return []byte{0x00, 0x00, 0x00, 0x00}
	case ServiceShapeFileObject, ServiceShapeModbus, ServiceShapePCCC, ServiceShapePayload, ServiceShapeSafetyReset:
		return []byte{0x00}
	default:
		return nil
	}
}

func BuildValidationPackets(spec ValidationPCAPSpec) ([]ValidationPacket, error) {
	prevProfile := cipclient.CurrentProtocolProfile()
	cipclient.SetProtocolProfile(cipclient.StrictODVAProfile)
	defer cipclient.SetProtocolProfile(prevProfile)

	validator := cipclient.NewPacketValidator(true)
	packets := make([]ValidationPacket, 0, len(spec.Requests)*2)
	senderContext := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	sessionID := uint32(0x12345678)

	for _, reqSpec := range spec.Requests {
		req := reqSpec.Req
		if reqSpec.PayloadType != "" || len(reqSpec.PayloadParams) > 0 {
			result, err := cipclient.BuildServicePayload(req, cipclient.PayloadSpec{
				Type:   reqSpec.PayloadType,
				Params: reqSpec.PayloadParams,
			})
			if err != nil {
				return nil, fmt.Errorf("build payload (%s): %w", reqSpec.Name, err)
			}
			if len(result.Payload) > 0 {
				req.Payload = result.Payload
			}
			if len(result.RawPath) > 0 {
				req.RawPath = result.RawPath
			}
		}

		if err := validator.ValidateCIPRequest(req); err != nil {
			return nil, fmt.Errorf("validate request (%s): %w", reqSpec.Name, err)
		}
		cipData, err := protocol.EncodeCIPRequest(req)
		if err != nil {
			return nil, fmt.Errorf("encode request (%s): %w", reqSpec.Name, err)
		}
		packet := enip.BuildSendRRData(sessionID, senderContext, cipData)
		encap, err := enip.DecodeENIP(packet)
		if err != nil {
			return nil, fmt.Errorf("decode ENIP (%s): %w", reqSpec.Name, err)
		}
		if err := validator.ValidateENIP(encap); err != nil {
			return nil, fmt.Errorf("validate ENIP (%s): %w", reqSpec.Name, err)
		}

		packets = append(packets, ValidationPacket{
			Data:   packet,
			Expect: buildPacketExpectation(reqSpec, "request"),
		})

		if reqSpec.IncludeResponse {
			resp, err := buildResponseForRequest(req, reqSpec)
			if err != nil {
				return nil, fmt.Errorf("build response (%s): %w", reqSpec.Name, err)
			}
			if resp != nil {
				respData, err := protocol.EncodeCIPResponse(*resp)
				if err != nil {
					return nil, fmt.Errorf("encode response (%s): %w", reqSpec.Name, err)
				}
				respPacket := enip.BuildSendRRData(sessionID, senderContext, respData)
				packets = append(packets, ValidationPacket{
					Data:   respPacket,
					Expect: buildPacketExpectation(reqSpec, "response"),
				})
			}
		}
	}
	return packets, nil
}

func BuildValidationENIPPackets(spec ValidationPCAPSpec) ([][]byte, error) {
	packets, err := BuildValidationPackets(spec)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(packets))
	for _, pkt := range packets {
		out = append(out, pkt.Data)
	}
	return out, nil
}

func WriteENIPPCAP(path string, packets []ValidationPacket) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pcap: %w", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}

	type flowState struct {
		port      uint16
		clientSeq uint32
		serverSeq uint32
	}
	baseFlows := map[string]*flowState{}
	nextPort := uint16(50000)
	for _, packet := range packets {
		baseID := strings.TrimSuffix(strings.TrimSuffix(packet.Expect.ID, "/request"), "/response")
		flow, ok := baseFlows[baseID]
		if !ok {
			flow = &flowState{port: nextPort, clientSeq: 1, serverSeq: 1}
			baseFlows[baseID] = flow
			nextPort++
		}
		srcIP := []byte{192, 168, 100, 10}
		dstIP := []byte{192, 168, 100, 20}
		srcPort := flow.port
		dstPort := uint16(44818)
		seq := flow.clientSeq
		ack := uint32(0)
		if packet.Expect.Direction == "response" {
			srcIP, dstIP = dstIP, srcIP
			srcPort, dstPort = dstPort, srcPort
			seq = flow.serverSeq
			ack = flow.clientSeq
		}
		buffer := gopacket.NewSerializeBuffer()
		opts := gopacket.SerializeOptions{
			FixLengths:       true,
			ComputeChecksums: true,
		}

		ethernet := &layers.Ethernet{
			SrcMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			DstMAC:       []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x02},
			EthernetType: layers.EthernetTypeIPv4,
		}
		ip := &layers.IPv4{
			Version:  4,
			TTL:      64,
			Protocol: layers.IPProtocolTCP,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(srcPort),
			DstPort: layers.TCPPort(dstPort),
			SYN:     false,
			ACK:     true,
			PSH:     true,
			Seq:     seq,
			Ack:     ack,
		}
		tcp.SetNetworkLayerForChecksum(ip)

		if packet.Expect.Direction == "response" {
			flow.serverSeq += uint32(len(packet.Data))
		} else {
			flow.clientSeq += uint32(len(packet.Data))
		}

		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ip, tcp, gopacket.Payload(packet.Data)); err != nil {
			return fmt.Errorf("serialize packet: %w", err)
		}
		if err := writer.WritePacket(gopacket.CaptureInfo{
			CaptureLength: len(buffer.Bytes()),
			Length:        len(buffer.Bytes()),
		}, buffer.Bytes()); err != nil {
			return fmt.Errorf("write packet: %w", err)
		}
	}

	return nil
}

func GenerateValidationPCAPs(outputDir string) ([]string, error) {
	specs, err := DefaultValidationPCAPSpecs()
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return nil, fmt.Errorf("create output dir: %w", err)
	}
	paths := make([]string, 0, len(specs))
	for _, spec := range specs {
		packets, err := BuildValidationPackets(spec)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(outputDir, fmt.Sprintf("validation_%s.pcap", spec.Name))
		expectations := make([]PacketExpectation, 0, len(packets))
		for _, pkt := range packets {
			expectations = append(expectations, pkt.Expect)
		}
		if err := WriteENIPPCAP(path, packets); err != nil {
			return nil, err
		}
		manifest := ValidationManifest{
			PCAP:    filepath.Base(path),
			Packets: expectations,
		}
		if err := WriteValidationManifest(ValidationManifestPath(path), manifest); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}
