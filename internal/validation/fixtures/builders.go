package fixtures

import (
	"fmt"
	"strings"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"github.com/tonylturner/cipdip/internal/enip"
	"github.com/tonylturner/cipdip/internal/validation"
)

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

func BuildValidationPackets(pcapSpec ValidationPCAPSpec) ([]ValidationPacket, error) {
	prevProfile := cipclient.CurrentProtocolProfile()
	cipclient.SetProtocolProfile(cipclient.StrictODVAProfile)
	defer cipclient.SetProtocolProfile(prevProfile)

	validator := validation.NewValidator(true, "client_wire", spec.DefaultRegistry())
	packets := make([]ValidationPacket, 0, len(pcapSpec.Requests)*2)
	senderContext := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	sessionID := uint32(0x12345678)

	for _, reqSpec := range pcapSpec.Requests {
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

		if !strings.EqualFold(reqSpec.Outcome, "invalid") {
			if err := validation.FindingsError(validator.ValidateCIPRequest(req)); err != nil {
				return nil, fmt.Errorf("validate request (%s): %w", reqSpec.Name, err)
			}
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
		if err := validation.FindingsError(validator.ValidateENIP(encap)); err != nil {
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

func BuildValidationENIPPackets(pcapSpec ValidationPCAPSpec) ([][]byte, error) {
	packets, err := BuildValidationPackets(pcapSpec)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(packets))
	for _, pkt := range packets {
		out = append(out, pkt.Data)
	}
	return out, nil
}
