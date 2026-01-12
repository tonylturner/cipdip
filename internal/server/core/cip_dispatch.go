package core

import (
	"fmt"
	"time"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/enip"
)

func (s *Server) handleSendRRData(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	session, ok := s.requireSession(encap.SessionID, remoteAddr)
	if !ok {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidSessionHandle)
	}

	if session != nil {
		session.mu.Lock()
		session.LastActivity = time.Now()
		session.mu.Unlock()
	}

	cipData, err := s.parseSendRRData(encap.Data)
	if err != nil {
		s.logger.Error("Parse SendRRData error: %v", err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	if len(cipData) > 0 && protocol.CIPServiceCode(cipData[0]) == spec.CIPServiceForwardOpen {
		return s.handleForwardOpen(encap, cipData, remoteAddr)
	}

	if len(cipData) > 0 && protocol.CIPServiceCode(cipData[0]) == spec.CIPServiceForwardClose {
		return s.handleForwardClose(encap, cipData)
	}

	if len(cipData) > 0 && protocol.CIPServiceCode(cipData[0]) == spec.CIPServiceLargeForwardOpen {
		return s.handleLargeForwardOpen(encap, cipData, remoteAddr)
	}

	cipReq, err := protocol.DecodeCIPRequest(cipData)
	if err != nil {
		s.logger.Error("Decode CIP request error: %v", err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	fmt.Printf("[SERVER] Received CIP request: service=0x%02X class=0x%04X instance=0x%04X attribute=0x%02X\n",
		uint8(cipReq.Service), cipReq.Path.Class, cipReq.Path.Instance, cipReq.Path.Attribute)
	if s.config.Logging.IncludeHexDump {
		s.logger.LogHex("CIP Request", cipData)
	}

	if policyResp, ok := s.applyCIPPolicy(cipReq); ok {
		cipRespData, err := protocol.EncodeCIPResponse(policyResp)
		if err != nil {
			s.logger.Error("Encode CIP response error: %v", err)
			return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	if cipReq.Service == spec.CIPServiceUnconnectedSend {
		return s.handleUnconnectedSend(encap, cipReq)
	}
	if cipReq.Service == spec.CIPServiceMultipleService {
		return s.handleMultipleService(encap, cipReq)
	}

	cipResp, handled, err := s.handlers.Handle(s.ctx, cipReq)
	if !handled {
		cipResp = protocol.CIPResponse{
			Service: cipReq.Service,
			Status:  0x08,
			Path:    cipReq.Path,
		}
	}
	if err != nil {
		s.logger.Error("Handle CIP request error: %v", err)
		fmt.Printf("[SERVER] Request failed: %v\n", err)
		cipResp = protocol.CIPResponse{
			Service: cipReq.Service,
			Status:  0x01,
			Path:    cipReq.Path,
		}
	} else {
		payloadSize := 0
		if cipResp.Payload != nil {
			payloadSize = len(cipResp.Payload)
		}
		fmt.Printf("[SERVER] Responded: service=0x%02X status=0x%02X payload=%d bytes\n",
			uint8(cipResp.Service), cipResp.Status, payloadSize)
	}

	cipRespData, err := protocol.EncodeCIPResponse(cipResp)
	if err != nil {
		s.logger.Error("Encode CIP response error: %v", err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	return s.buildCIPResponse(encap, cipRespData)
}

func (s *Server) handleSendUnitData(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	if _, ok := s.requireSession(encap.SessionID, remoteAddr); !ok {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidSessionHandle)
	}

	connectionID, cipData, err := s.parseSendUnitData(encap.Data)
	if err != nil {
		s.logger.Error("Parse SendUnitData error: %v", err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	if !s.isConnectionActive(connectionID, encap.SessionID) {
		s.logger.Error("SendUnitData for inactive connection %d from %s", connectionID, remoteAddr)
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidSessionHandle)
	}
	s.touchConnection(connectionID)

	s.logger.Debug("SendUnitData: connection %d, data length %d", connectionID, len(cipData))

	sendData := enip.BuildSendUnitDataPayload(connectionID, cipData)
	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendUnitData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}
	return enip.EncodeENIP(response)
}

func (s *Server) handleForwardOpen(encap enip.ENIPEncapsulation, cipData []byte, remoteAddr string) []byte {
	fmt.Printf("[SERVER] Received ForwardOpen request\n")

	s.sessionsMu.Lock()
	oToTConnID := uint32(0x10000000 + s.nextSessionID*2)
	tToOConnID := uint32(0x10000000 + s.nextSessionID*2 + 1)
	s.nextSessionID++
	s.sessionsMu.Unlock()

	order := cipclient.CurrentProtocolProfile().CIPByteOrder
	var respData []byte
	respData = append(respData, 0x00)
	respData = append(respData, 0x00)
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], oToTConnID)
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], tToOConnID)
	respData = append(respData, make([]byte, 2)...)
	codec.PutUint16(order, respData[len(respData)-2:], 0x0000)
	respData = append(respData, make([]byte, 2)...)
	codec.PutUint16(order, respData[len(respData)-2:], 0x0000)
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], 0x00000000)
	respData = append(respData, 0x01)

	sendData := enip.BuildSendRRDataPayload(respData)

	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	s.trackConnection(oToTConnID, encap.SessionID, remoteAddr)
	s.trackConnection(tToOConnID, encap.SessionID, remoteAddr)

	return enip.EncodeENIP(response)
}

func (s *Server) handleForwardClose(encap enip.ENIPEncapsulation, cipData []byte) []byte {
	fmt.Printf("[SERVER] Received ForwardClose request\n")

	connID := parseForwardCloseConnectionID(cipData)
	if connID != 0 {
		s.untrackConnection(connID)
	}

	respData := []byte{0x00, 0x00}
	sendData := enip.BuildSendRRDataPayload(respData)
	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}
	return enip.EncodeENIP(response)
}

// handleLargeForwardOpen handles Large Forward Open (0x5B) requests.
// Large Forward Open is similar to Forward Open but supports:
// - 32-bit connection serial numbers (vs 16-bit)
// - Larger connection path sizes
// - Extended connection parameters
func (s *Server) handleLargeForwardOpen(encap enip.ENIPEncapsulation, cipData []byte, remoteAddr string) []byte {
	fmt.Printf("[SERVER] Received Large ForwardOpen request\n")

	s.sessionsMu.Lock()
	// Use higher connection ID range to distinguish from regular ForwardOpen
	oToTConnID := uint32(0x20000000 + s.nextSessionID*2)
	tToOConnID := uint32(0x20000000 + s.nextSessionID*2 + 1)
	connSerialNumber := s.nextSessionID
	s.nextSessionID++
	s.sessionsMu.Unlock()

	order := cipclient.CurrentProtocolProfile().CIPByteOrder

	// Build Large Forward Open response
	// Response structure (per ODVA CIP Vol 1, Chapter 3-5.5.2):
	// - O->T Connection ID (4 bytes)
	// - T->O Connection ID (4 bytes)
	// - Connection Serial Number (4 bytes) - 32-bit for Large Forward Open
	// - Originator Vendor ID (2 bytes)
	// - Originator Serial Number (4 bytes)
	// - O->T API (4 bytes)
	// - T->O API (4 bytes)
	// - Application Reply Size (1 byte)
	// - Reserved (1 byte)
	// - Application Reply Data (variable)

	var respData []byte

	// O->T Connection ID
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], oToTConnID)

	// T->O Connection ID
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], tToOConnID)

	// Connection Serial Number (32-bit for Large Forward Open)
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], connSerialNumber)

	// Originator Vendor ID (echo from request or use default)
	respData = append(respData, make([]byte, 2)...)
	codec.PutUint16(order, respData[len(respData)-2:], 0x0001) // Default vendor ID

	// Originator Serial Number (echo from request or use default)
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], 0x12345678) // Default serial

	// O->T API (Actual Packet Interval in microseconds)
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], 20000) // 20ms default

	// T->O API
	respData = append(respData, make([]byte, 4)...)
	codec.PutUint32(order, respData[len(respData)-4:], 20000) // 20ms default

	// Application Reply Size (0 = no application reply)
	respData = append(respData, 0x00)

	// Reserved
	respData = append(respData, 0x00)

	sendData := enip.BuildSendRRDataPayload(respData)

	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandSendRRData,
		Length:        uint16(len(sendData)),
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          sendData,
	}

	s.trackConnection(oToTConnID, encap.SessionID, remoteAddr)
	s.trackConnection(tToOConnID, encap.SessionID, remoteAddr)

	return enip.EncodeENIP(response)
}

func (s *Server) handleUnconnectedSend(encap enip.ENIPEncapsulation, req protocol.CIPRequest) []byte {
	embedded, routePath, ok := protocol.ParseUnconnectedSendRequestPayload(req.Payload)
	if !ok {
		resp := protocol.CIPResponse{
			Service: req.Service,
			Status:  0x13,
			Path:    req.Path,
		}
		cipRespData, err := protocol.EncodeCIPResponse(resp)
		if err != nil {
			return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	embeddedReq, err := protocol.DecodeCIPRequest(embedded)
	if err != nil {
		resp := protocol.CIPResponse{
			Service: req.Service,
			Status:  0x13,
			Path:    req.Path,
		}
		cipRespData, err := protocol.EncodeCIPResponse(resp)
		if err != nil {
			return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	_ = routePath
	embeddedResp := s.handleEmbeddedRequest(embeddedReq)
	embeddedRespData, err := protocol.EncodeCIPResponse(embeddedResp)
	if err != nil {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	respPayload := cipclient.BuildUnconnectedSendResponsePayload(embeddedRespData)
	resp := protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
		Payload: respPayload,
	}
	cipRespData, err := protocol.EncodeCIPResponse(resp)
	if err != nil {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}
	return s.buildCIPResponse(encap, cipRespData)
}

func (s *Server) handleMultipleService(encap enip.ENIPEncapsulation, req protocol.CIPRequest) []byte {
	requests, err := cipclient.ParseMultipleServiceRequestPayload(req.Payload)
	if err != nil {
		resp := protocol.CIPResponse{
			Service: req.Service,
			Status:  0x13,
			Path:    req.Path,
		}
		cipRespData, err := protocol.EncodeCIPResponse(resp)
		if err != nil {
			return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
		}
		return s.buildCIPResponse(encap, cipRespData)
	}

	responses := make([]protocol.CIPResponse, 0, len(requests))
	for _, embeddedReq := range requests {
		responses = append(responses, s.handleEmbeddedRequest(embeddedReq))
	}

	payload, err := cipclient.BuildMultipleServiceResponsePayload(responses)
	if err != nil {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	resp := protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
		Payload: payload,
	}
	cipRespData, err := protocol.EncodeCIPResponse(resp)
	if err != nil {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}
	return s.buildCIPResponse(encap, cipRespData)
}

func (s *Server) handleEmbeddedRequest(req protocol.CIPRequest) protocol.CIPResponse {
	resp, handled, err := s.handlers.Handle(s.ctx, req)
	if !handled {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}
	}
	if err != nil {
		return protocol.CIPResponse{Service: req.Service, Status: 0x01, Path: req.Path}
	}
	return resp
}

func parseForwardCloseConnectionID(cipData []byte) uint32 {
	order := cipclient.CurrentProtocolProfile().CIPByteOrder
	for i := 0; i+5 <= len(cipData); i++ {
		if cipData[i] == 0x34 && i+5 <= len(cipData) {
			return order.Uint32(cipData[i+1 : i+5])
		}
	}
	return 0
}
