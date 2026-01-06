package fixtures

import (
	"fmt"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
)

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
