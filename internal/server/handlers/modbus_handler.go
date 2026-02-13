package handlers

// Modbus CIP handler: processes Modbus PDUs tunneled through CIP class 0x44.
//
// When an EtherNet/IP device exposes Modbus registers via the CIP
// Modbus Object (class 0x44), CIP service requests carry raw Modbus
// PDUs in their payloads. This handler decodes the PDU, dispatches
// to a DataStore, and returns the Modbus response wrapped in CIP.

import (
	"context"
	"fmt"
	"sync"

	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/logging"
	"github.com/tonylturner/cipdip/internal/modbus"
)

// ModbusHandler handles CIP requests targeting the Modbus Object (class 0x44).
type ModbusHandler struct {
	store  *modbus.DataStore
	logger *logging.Logger
	mu     sync.RWMutex
	stats  ModbusStats
}

// ModbusStats tracks Modbus handler metrics.
type ModbusStats struct {
	TotalRequests int64
	ReadRequests  int64
	WriteRequests int64
	Exceptions    int64
}

// NewModbusHandler creates a Modbus handler backed by the given data store.
func NewModbusHandler(store *modbus.DataStore, logger *logging.Logger) *ModbusHandler {
	return &ModbusHandler{
		store:  store,
		logger: logger,
	}
}

// HandleCIPRequest processes a CIP request targeting the Modbus Object.
// The CIP payload contains a raw Modbus PDU (function code + data).
func (h *ModbusHandler) HandleCIPRequest(_ context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	h.mu.Lock()
	h.stats.TotalRequests++
	h.mu.Unlock()

	if len(req.Payload) < 1 {
		return protocol.CIPResponse{
			Service: req.Service | 0x80,
			Path:    req.Path,
			Status:  0x04, // path segment error
		}, nil
	}

	// Decode the Modbus PDU from the CIP payload.
	modbusReq, err := modbus.DecodeCIPTunnelRequest(req.Payload, uint8(req.Path.Instance))
	if err != nil {
		return protocol.CIPResponse{
			Service: req.Service | 0x80,
			Path:    req.Path,
			Status:  0x04,
		}, nil
	}

	h.logger.Verbose("Modbus request: FC=0x%02X unit=%d data=%d bytes",
		modbusReq.Function, modbusReq.UnitID, len(modbusReq.Data))

	// Track read vs write
	h.mu.Lock()
	if modbusReq.Function.IsRead() {
		h.stats.ReadRequests++
	} else if modbusReq.Function.IsWrite() {
		h.stats.WriteRequests++
	}
	h.mu.Unlock()

	// Dispatch to data store.
	modbusResp := h.store.HandleRequest(modbusReq)

	if modbusResp.IsException() {
		h.mu.Lock()
		h.stats.Exceptions++
		h.mu.Unlock()
		h.logger.Verbose("Modbus exception: FC=0x%02X exc=%v",
			modbusResp.Function, modbusResp.ExceptionCode())
	}

	// Encode Modbus response back into CIP payload.
	respPayload := modbus.EncodeCIPTunnelResponse(modbusResp)

	return protocol.CIPResponse{
		Service: req.Service | 0x80,
		Path:    req.Path,
		Status:  0, // success - Modbus exceptions are in the payload
		Payload: respPayload,
	}, nil
}

// Stats returns a snapshot of handler statistics.
func (h *ModbusHandler) Stats() ModbusStats {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.stats
}

// String returns a description of this handler.
func (h *ModbusHandler) String() string {
	return fmt.Sprintf("ModbusHandler(class=0x%04X)", modbus.CIPModbusClass)
}
