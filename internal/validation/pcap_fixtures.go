package validation

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/tturner/cipdip/internal/cipclient"
)

type ValidationRequestSpec struct {
	Name            string
	Req             cipclient.CIPRequest
	PayloadType     string
	PayloadParams   map[string]any
	ServiceShape    string
	IncludeResponse bool
	ExpectSymbol    bool
}

type ValidationPCAPSpec struct {
	Name     string
	Requests []ValidationRequestSpec
}

func DefaultValidationPCAPSpecs() ([]ValidationPCAPSpec, error) {
	embeddedReq := cipclient.CIPRequest{
		Service: cipclient.CIPServiceGetAttributeSingle,
		Path: cipclient.CIPPath{
			Class:     cipclient.CIPClassIdentityObject,
			Instance:  0x01,
			Attribute: 0x01,
		},
	}
	embeddedBytes, err := cipclient.EncodeCIPRequest(embeddedReq)
	if err != nil {
		return nil, fmt.Errorf("encode embedded request: %w", err)
	}

	cases := []ValidationPCAPSpec{
		{
			Name: "common_services",
			Requests: append(commonServiceRequests(), ValidationRequestSpec{
				Name: "multiple_service_packet",
				Req:  buildMultipleServiceRequest(),
			}),
		},
		{
			Name: "core",
			Requests: []ValidationRequestSpec{
				{
					Name: "get_attribute_single",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceGetAttributeSingle,
						Path: cipclient.CIPPath{
							Class:     cipclient.CIPClassIdentityObject,
							Instance:  0x01,
							Attribute: 0x01,
						},
					},
					ServiceShape:    ServiceShapeNone,
					IncludeResponse: true,
				},
				{
					Name: "set_attribute_single",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceSetAttributeSingle,
						Path: cipclient.CIPPath{
							Class:     cipclient.CIPClassAssembly,
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
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceForwardOpen,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassConnectionManager, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadForwardOpen),
					PayloadParams: map[string]any{
						"connection_class":    uint64(cipclient.CIPClassAssembly),
						"connection_instance": uint64(0x65),
					},
					ServiceShape:    ServiceShapeForwardOpen,
					IncludeResponse: true,
				},
				{
					Name: "forward_close",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceForwardClose,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassConnectionManager, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadForwardClose),
					PayloadParams: map[string]any{
						"connection_id": uint64(0x11223344),
					},
					ServiceShape:    ServiceShapeForwardClose,
					IncludeResponse: true,
				},
				{
					Name: "unconnected_send",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceUnconnectedSend,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassConnectionManager, Instance: 0x01},
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
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceReadTag,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassSymbolObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTag),
					PayloadParams: map[string]any{
						"tag": "TestTag",
					},
				},
				{
					Name: "write_tag",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceWriteTag,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassSymbolObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTag),
					PayloadParams: map[string]any{
						"tag":   "TestTag",
						"type":  "DINT",
						"value": "123",
					},
				},
				{
					Name: "read_tag_fragmented",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceReadTagFragmented,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassSymbolObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTagFrag),
					PayloadParams: map[string]any{
						"tag":    "TestTag",
						"offset": uint64(0),
					},
				},
				{
					Name: "write_tag_fragmented",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceWriteTagFragmented,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassSymbolObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTagFrag),
					PayloadParams: map[string]any{
						"tag":    "TestTag",
						"type":   "DINT",
						"value":  "456",
						"offset": uint64(0),
					},
				},
				{
					Name: "execute_pccc",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceExecutePCCC,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassPCCCObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellPCCC),
					PayloadParams: map[string]any{
						"pccc_hex": "0f00",
					},
				},
				{
					Name: "template_read",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceReadTag,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassTemplateObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadRockwellTemplate),
					PayloadParams: map[string]any{
						"offset": uint64(0),
						"length": uint64(64),
					},
				},
			},
		},
		{
			Name: "file_modbus",
			Requests: []ValidationRequestSpec{
				{
					Name: "file_initiate_upload",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceInitiateUpload,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"file_size": uint64(1024),
					},
				},
				{
					Name: "file_initiate_download",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceInitiateDownload,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"file_size":      uint64(512),
						"format_version": uint64(1),
						"file_revision":  uint64(1),
						"file_name":      "test.bin",
					},
				},
				{
					Name: "file_partial_read",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceInitiatePartialRead,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"file_offset": uint64(0),
						"chunk":       uint64(32),
					},
				},
				{
					Name: "file_partial_write",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceInitiatePartialWrite,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"file_offset": uint64(0),
						"data_hex":    "01020304",
					},
				},
				{
					Name: "file_upload_transfer",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceUploadTransfer,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"transfer_number": uint64(1),
					},
				},
				{
					Name: "file_download_transfer",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceDownloadTransfer,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
					PayloadParams: map[string]any{
						"transfer_number": uint64(1),
						"transfer_type":   uint64(1),
						"data_hex":        "0102",
					},
				},
				{
					Name: "file_clear",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceClearFile,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassFileObject, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadFileObject),
				},
				{
					Name: "modbus_read_discrete_inputs",
					Req: cipclient.CIPRequest{
						Service: 0x4B,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassModbus, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadModbusObject),
					PayloadParams: map[string]any{
						"modbus_addr": uint64(0),
						"modbus_qty":  uint64(2),
					},
				},
				{
					Name: "modbus_write_holding_registers",
					Req: cipclient.CIPRequest{
						Service: 0x50,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassModbus, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadModbusObject),
					PayloadParams: map[string]any{
						"modbus_addr":     uint64(1),
						"modbus_qty":      uint64(1),
						"modbus_data_hex": "0001",
					},
				},
				{
					Name: "modbus_passthrough",
					Req: cipclient.CIPRequest{
						Service: 0x51,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassModbus, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadModbusObject),
					PayloadParams: map[string]any{
						"modbus_pdu_hex": "03",
					},
				},
			},
		},
		{
			Name: "safety_energy_motion",
			Requests: []ValidationRequestSpec{
				{
					Name: "safety_reset",
					Req: cipclient.CIPRequest{
						Service: 0x54,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassSafetySupervisor, Instance: 0x01},
					},
					PayloadType: string(cipclient.PayloadSafetyReset),
					PayloadParams: map[string]any{
						"reset_type": uint64(0),
					},
				},
				{
					Name: "energy_start_metering",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceExecutePCCC,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassEnergyBase, Instance: 0x01},
						Payload: []byte{0x00},
					},
				},
				{
					Name: "motion_axis_list",
					Req: cipclient.CIPRequest{
						Service: cipclient.CIPServiceExecutePCCC,
						Path:    cipclient.CIPPath{Class: cipclient.CIPClassMotionAxis, Instance: 0x01},
						Payload: []byte{0x00},
					},
				},
			},
		},
	}

	return cases, nil
}

func commonServiceRequests() []ValidationRequestSpec {
	path := cipclient.CIPPath{
		Class:     cipclient.CIPClassIdentityObject,
		Instance:  0x01,
		Attribute: 0x01,
	}
	assemblyPath := cipclient.CIPPath{
		Class:     cipclient.CIPClassAssembly,
		Instance:  0x65,
		Attribute: 0x03,
	}
	attrList := buildAttributeListPayload([]uint16{0x01})
	setAttrList := buildSetAttributeListPayload([]uint16{0x01}, [][]byte{{0x01, 0x00}})

	return []ValidationRequestSpec{
		{Name: "get_attribute_all", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceGetAttributeAll, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "set_attribute_all", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceSetAttributeAll, Path: assemblyPath, Payload: []byte{0x00}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "get_attribute_list", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceGetAttributeList, Path: path, Payload: attrList}, ServiceShape: ServiceShapeRead, IncludeResponse: true},
		{Name: "set_attribute_list", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceSetAttributeList, Path: assemblyPath, Payload: setAttrList}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "reset", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceReset, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "start", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceStart, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "stop", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceStop, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "create", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceCreate, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "delete", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceDelete, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "apply_attributes", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceApplyAttributes, Path: assemblyPath}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_attribute_single", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceGetAttributeSingle, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "set_attribute_single", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceSetAttributeSingle, Path: assemblyPath, Payload: []byte{0x01, 0x00}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "find_next_object_instance", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceFindNextObjectInst, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "restore", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceRestore, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "save", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceSave, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "nop", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceNoOp, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_member", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceGetMember, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "set_member", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceSetMember, Path: path, Payload: []byte{0x00, 0x01}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "insert_member", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceInsertMember, Path: path, Payload: []byte{0x00, 0x01}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "remove_member", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceRemoveMember, Path: path, Payload: []byte{0x00, 0x01}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
		{Name: "group_sync", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceGroupSync, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_instance_attribute_list", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceGetInstanceAttrList, Path: path}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_connection_data", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceGetConnectionData, Path: cipclient.CIPPath{Class: cipclient.CIPClassConnectionManager, Instance: 0x01}}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "search_connection_data", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceSearchConnectionData, Path: cipclient.CIPPath{Class: cipclient.CIPClassConnectionManager, Instance: 0x01}}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "get_connection_owner", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceGetConnectionOwner, Path: cipclient.CIPPath{Class: cipclient.CIPClassConnectionManager, Instance: 0x01}}, ServiceShape: ServiceShapeNone, IncludeResponse: true},
		{Name: "large_forward_open", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceLargeForwardOpen, Path: cipclient.CIPPath{Class: cipclient.CIPClassConnectionManager, Instance: 0x01}, Payload: []byte{0x00}}, ServiceShape: ServiceShapePayload, IncludeResponse: true},
		{Name: "read_modify_write", Req: cipclient.CIPRequest{Service: cipclient.CIPServiceReadModifyWrite, Path: assemblyPath, Payload: []byte{0x00}}, ServiceShape: ServiceShapeWrite, IncludeResponse: true},
	}
}

func buildMultipleServiceRequest() cipclient.CIPRequest {
	req1 := cipclient.CIPRequest{
		Service: cipclient.CIPServiceGetAttributeSingle,
		Path: cipclient.CIPPath{
			Class:     cipclient.CIPClassIdentityObject,
			Instance:  0x01,
			Attribute: 0x01,
		},
	}
	req2 := cipclient.CIPRequest{
		Service: cipclient.CIPServiceSetAttributeSingle,
		Path: cipclient.CIPPath{
			Class:     cipclient.CIPClassAssembly,
			Instance:  0x65,
			Attribute: 0x03,
		},
		Payload: []byte{0x01, 0x00},
	}
	request, err := cipclient.BuildMultipleServiceRequest([]cipclient.CIPRequest{req1, req2})
	if err != nil {
		return cipclient.CIPRequest{
			Service: cipclient.CIPServiceMultipleService,
			Path: cipclient.CIPPath{
				Class:    cipclient.CIPClassMessageRouter,
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
	order.PutUint16(buf[:2], uint16(len(attrs)))
	offset := 2
	for _, attr := range attrs {
		order.PutUint16(buf[offset:offset+2], attr)
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
	order.PutUint16(buf[:2], uint16(len(attrs)))
	for i, attr := range attrs {
		buf = appendUint16Local(order, buf, attr)
		if i < len(values) && len(values[i]) > 0 {
			buf = append(buf, values[i]...)
		} else {
			buf = append(buf, 0x00)
		}
	}
	return buf
}

func appendUint16Local(order binary.ByteOrder, buf []byte, value uint16) []byte {
	var tmp [2]byte
	order.PutUint16(tmp[:], value)
	return append(buf, tmp[:]...)
}

func BuildValidationENIPPackets(spec ValidationPCAPSpec) ([][]byte, error) {
	validator := cipclient.NewPacketValidator(true)
	enipPackets := make([][]byte, 0, len(spec.Requests))
	for _, spec := range spec.Requests {
		req := spec.Req
		if spec.PayloadType != "" || len(spec.PayloadParams) > 0 {
			result, err := cipclient.BuildServicePayload(req, cipclient.PayloadSpec{
				Type:   spec.PayloadType,
				Params: spec.PayloadParams,
			})
			if err != nil {
				return nil, fmt.Errorf("build payload (%s): %w", spec.Name, err)
			}
			if len(result.Payload) > 0 {
				req.Payload = result.Payload
			}
			if len(result.RawPath) > 0 {
				req.RawPath = result.RawPath
			}
		}

		if err := validator.ValidateCIPRequest(req); err != nil {
			return nil, fmt.Errorf("validate request (%s): %w", spec.Name, err)
		}
		cipData, err := cipclient.EncodeCIPRequest(req)
		if err != nil {
			return nil, fmt.Errorf("encode request (%s): %w", spec.Name, err)
		}
		packet := cipclient.BuildSendRRData(0x12345678, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, cipData)
		encap, err := cipclient.DecodeENIP(packet)
		if err != nil {
			return nil, fmt.Errorf("decode ENIP (%s): %w", spec.Name, err)
		}
		if err := validator.ValidateENIP(encap); err != nil {
			return nil, fmt.Errorf("validate ENIP (%s): %w", spec.Name, err)
		}
		enipPackets = append(enipPackets, packet)
	}
	return enipPackets, nil
}

func WriteENIPPCAP(path string, packets [][]byte) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create pcap: %w", err)
	}
	defer file.Close()

	writer := pcapgo.NewWriter(file)
	if err := writer.WriteFileHeader(65535, layers.LinkTypeEthernet); err != nil {
		return fmt.Errorf("write pcap header: %w", err)
	}

	for i, packet := range packets {
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
			SrcIP:    []byte{192, 168, 100, 10},
			DstIP:    []byte{192, 168, 100, 20},
		}
		tcp := &layers.TCP{
			SrcPort: layers.TCPPort(50000 + i),
			DstPort: 44818,
			SYN:     false,
			ACK:     true,
			PSH:     true,
			Seq:     uint32(1 + i),
		}
		tcp.SetNetworkLayerForChecksum(ip)

		if err := gopacket.SerializeLayers(buffer, opts, ethernet, ip, tcp, gopacket.Payload(packet)); err != nil {
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
		packets, err := BuildValidationENIPPackets(spec)
		if err != nil {
			return nil, err
		}
		path := filepath.Join(outputDir, fmt.Sprintf("validation_%s.pcap", spec.Name))
		if err := WriteENIPPCAP(path, packets); err != nil {
			return nil, err
		}
		paths = append(paths, path)
	}
	return paths, nil
}
