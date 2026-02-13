package core

import (
	"fmt"
	"net"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/codec"
	"github.com/tonylturner/cipdip/internal/enip"
)

func (s *Server) handleENIPCommand(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	s.recordRequest()
	switch encap.Command {
	case enip.ENIPCommandRegisterSession:
		if !s.enipSupport.registerSession {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleRegisterSession(encap, remoteAddr)

	case enip.ENIPCommandUnregisterSession:
		if !s.enipSupport.registerSession {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleUnregisterSession(encap)

	case enip.ENIPCommandSendRRData:
		if !s.enipSupport.sendRRData {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleSendRRData(encap, remoteAddr)

	case enip.ENIPCommandSendUnitData:
		if !s.enipSupport.sendUnitData {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleSendUnitData(encap, remoteAddr)

	case enip.ENIPCommandListIdentity:
		if !s.enipSupport.listIdentity {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleListIdentity(encap, remoteAddr)

	case enip.ENIPCommandListServices:
		if !s.enipSupport.listServices {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleListServices(encap)

	case enip.ENIPCommandListInterfaces:
		if !s.enipSupport.listInterfaces {
			return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
		}
		return s.handleListInterfaces(encap)

	default:
		s.logger.Error("Unsupported ENIP command 0x%04X from %s", encap.Command, remoteAddr)
		return s.buildErrorResponse(encap, enip.ENIPStatusUnsupportedCommand)
	}
}

func (s *Server) handleRegisterSession(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	if len(encap.Data) < 4 {
		return s.buildErrorResponse(encap, enip.ENIPStatusInvalidLength)
	}

	if err := s.enforceSessionLimits(remoteAddr); err != nil {
		s.logger.Error("RegisterSession rejected from %s: %v", remoteAddr, err)
		return s.buildErrorResponse(encap, enip.ENIPStatusInsufficientMemory)
	}

	s.sessionsMu.Lock()
	sessionID := s.nextSessionID
	s.nextSessionID++
	s.sessionsMu.Unlock()

	session := &Session{
		ID:           sessionID,
		RemoteIP:     remoteIP(remoteAddr),
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
	}

	s.sessionsMu.Lock()
	s.sessions[sessionID] = session
	s.sessionsMu.Unlock()

	s.logger.Info("Registered session %d", sessionID)
	fmt.Printf("[SERVER] Registered session %d\n", sessionID)

	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandRegisterSession,
		Length:        4,
		SessionID:     sessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          encap.Data,
	}

	return enip.EncodeENIP(response)
}

func (s *Server) handleUnregisterSession(encap enip.ENIPEncapsulation) []byte {
	s.sessionsMu.Lock()
	delete(s.sessions, encap.SessionID)
	s.sessionsMu.Unlock()

	s.logger.Info("Unregistered session %d", encap.SessionID)
	fmt.Printf("[SERVER] Unregistered session %d\n", encap.SessionID)

	response := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandUnregisterSession,
		Length:        0,
		SessionID:     encap.SessionID,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}

	return enip.EncodeENIP(response)
}

func (s *Server) handleListIdentity(encap enip.ENIPEncapsulation, remoteAddr string) []byte {
	vendorID, deviceType, productCode, revMajor, revMinor, status, serial, productName := s.identityValues()
	order := cipclient.CurrentProtocolProfile().ENIPByteOrder

	data := make([]byte, 0, 34+len(productName))
	socket := make([]byte, 16)
	codec.PutUint16(order, socket[0:2], 0x0002)
	codec.PutUint16(order, socket[2:4], uint16(s.config.Server.TCPPort))
	copy(socket[4:8], net.ParseIP(s.config.Server.ListenIP).To4())
	data = append(data, socket...)

	buf2 := make([]byte, 2)
	buf4 := make([]byte, 4)
	codec.PutUint16(order, buf2, vendorID)
	data = append(data, buf2...)
	codec.PutUint16(order, buf2, deviceType)
	data = append(data, buf2...)
	codec.PutUint16(order, buf2, productCode)
	data = append(data, buf2...)
	data = append(data, revMajor, revMinor)
	codec.PutUint16(order, buf2, status)
	data = append(data, buf2...)
	codec.PutUint32(order, buf4, serial)
	data = append(data, buf4...)
	data = append(data, byte(len(productName)))
	data = append(data, []byte(productName)...)
	data = append(data, 0x03)

	resp := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandListIdentity,
		Length:        uint16(len(data)),
		SessionID:     0,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          data,
	}
	return enip.EncodeENIP(resp)
}

func (s *Server) handleListServices(encap enip.ENIPEncapsulation) []byte {
	resp := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandListServices,
		Length:        0,
		SessionID:     0,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}
	return enip.EncodeENIP(resp)
}

func (s *Server) handleListInterfaces(encap enip.ENIPEncapsulation) []byte {
	resp := enip.ENIPEncapsulation{
		Command:       enip.ENIPCommandListInterfaces,
		Length:        0,
		SessionID:     0,
		Status:        enip.ENIPStatusSuccess,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}
	return enip.EncodeENIP(resp)
}

func (s *Server) buildCIPResponse(encap enip.ENIPEncapsulation, cipRespData []byte) []byte {
	sendData := enip.BuildSendRRDataPayload(cipRespData)
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

func (s *Server) buildErrorResponse(encap enip.ENIPEncapsulation, status uint32) []byte {
	response := enip.ENIPEncapsulation{
		Command:       encap.Command,
		Length:        0,
		SessionID:     encap.SessionID,
		Status:        status,
		SenderContext: encap.SenderContext,
		Options:       0,
		Data:          nil,
	}
	return enip.EncodeENIP(response)
}
