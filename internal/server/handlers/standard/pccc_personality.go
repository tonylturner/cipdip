package standard

// PCCC server personality - emulates an AB PLC-5/SLC-500 device with
// in-memory data tables. Handles Execute PCCC (service 0x4B) requests
// by decoding PCCC commands and reading/writing from data table storage.

import (
	"context"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
	"github.com/tturner/cipdip/internal/pccc"
)

// PCCCPersonality implements a PCCC/SLC-500 server personality with
// in-memory data tables.
type PCCCPersonality struct {
	config   *config.ServerConfig
	logger   *logging.Logger
	tables   *pccc.DataTableSet
	tnsCount uint16
	mu       sync.RWMutex
}

// NewPCCCPersonality creates a PCCC personality with default SLC-500 data tables.
func NewPCCCPersonality(cfg *config.ServerConfig, logger *logging.Logger) (*PCCCPersonality, error) {
	tables := pccc.NewDataTableSet()

	// Populate with configured initial values if present
	for _, init := range cfg.PCCCDataTables {
		ft, err := parsePCCCFileType(init.FileType)
		if err != nil {
			return nil, fmt.Errorf("pccc_data_tables: %w", err)
		}
		dt := pccc.NewDataTable(ft, init.FileNumber, init.Elements)
		tables.Tables[init.FileNumber] = dt
	}

	return &PCCCPersonality{
		config: cfg,
		logger: logger,
		tables: tables,
	}, nil
}

// HandleCIPRequest processes CIP requests for the PCCC personality.
func (p *PCCCPersonality) HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	switch req.Service {
	case spec.CIPServiceExecutePCCC:
		return p.handleExecutePCCC(req)

	case spec.CIPServiceGetAttributeSingle:
		return p.handleGetAttribute(req)

	case spec.CIPServiceGetAttributeAll:
		return p.handleGetAttributeAll(req)

	default:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08, // Service not supported
			Path:    req.Path,
		}, nil
	}
}

// handleExecutePCCC processes Execute PCCC (0x4B) requests.
func (p *PCCCPersonality) handleExecutePCCC(req protocol.CIPRequest) (protocol.CIPResponse, error) {
	// Validate class - only PCCC Object (0x67) and class 0
	if req.Path.Class != 0 && req.Path.Class != spec.CIPClassPCCCObject {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}, nil
	}

	if len(req.Payload) < pccc.MinRequestLen {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x01, // General error
			Path:    req.Path,
		}, nil
	}

	pcccReq, err := pccc.DecodeRequest(req.Payload)
	if err != nil {
		p.logger.Debug("PCCC decode error: %v", err)
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x01,
			Path:    req.Path,
		}, nil
	}

	pcccResp := p.processPCCCCommand(pcccReq)
	respBytes := pccc.EncodeResponse(pcccResp)

	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
		Payload: respBytes,
	}, nil
}

// processPCCCCommand dispatches a PCCC command to the appropriate handler.
func (p *PCCCPersonality) processPCCCCommand(req pccc.Request) pccc.Response {
	base := pccc.Response{
		Command: req.Command,
		Status:  0,
		TNS:     req.TNS,
	}

	if !req.Command.HasFunctionCode() {
		// Simple commands (protected read/write) - return success with empty data
		return base
	}

	base.Function = req.Function

	switch req.Function {
	case pccc.FncTypedRead:
		return p.handleTypedRead(req, base)
	case pccc.FncTypedWrite:
		return p.handleTypedWrite(req, base)
	case pccc.FncEcho:
		base.Data = req.Data // Echo back the data
		return base
	case pccc.FncDiagnosticRead:
		return p.handleDiagnosticRead(base)
	default:
		// Unknown function - return success with no data
		return base
	}
}

// handleTypedRead reads data from a data table.
func (p *PCCCPersonality) handleTypedRead(req pccc.Request, base pccc.Response) pccc.Response {
	p.mu.RLock()
	defer p.mu.RUnlock()

	data, err := p.tables.HandleTypedRead(req.Data)
	if err != nil {
		p.logger.Debug("PCCC typed read error: %v", err)
		base.Status = 0x10 // Illegal address
		base.ExtSTS = 0x01
		return base
	}

	base.Data = data
	return base
}

// handleTypedWrite writes data to a data table.
func (p *PCCCPersonality) handleTypedWrite(req pccc.Request, base pccc.Response) pccc.Response {
	p.mu.Lock()
	defer p.mu.Unlock()

	if err := p.tables.HandleTypedWrite(req.Data); err != nil {
		p.logger.Debug("PCCC typed write error: %v", err)
		base.Status = 0x10 // Illegal address
		base.ExtSTS = 0x01
		return base
	}

	return base
}

// handleDiagnosticRead returns mock diagnostic counters.
func (p *PCCCPersonality) handleDiagnosticRead(base pccc.Response) pccc.Response {
	// Return 20 bytes of diagnostic counters (all zeros = no errors)
	base.Data = make([]byte, 20)
	return base
}

// handleGetAttribute returns attributes for the PCCC object.
func (p *PCCCPersonality) handleGetAttribute(req protocol.CIPRequest) (protocol.CIPResponse, error) {
	var payload []byte

	switch req.Path.Class {
	case spec.CIPClassPCCCObject:
		switch req.Path.Attribute {
		case 1: // Revision
			payload = make([]byte, 2)
			binary.LittleEndian.PutUint16(payload, 1)
		case 2: // Max Instance
			payload = make([]byte, 2)
			binary.LittleEndian.PutUint16(payload, 1)
		default:
			payload = []byte{0x00}
		}
	default:
		payload = []byte{0x00}
	}

	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
		Payload: payload,
	}, nil
}

// handleGetAttributeAll returns all attributes for the PCCC object.
func (p *PCCCPersonality) handleGetAttributeAll(req protocol.CIPRequest) (protocol.CIPResponse, error) {
	// Return minimal identity: revision(2) + max_instance(2)
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint16(payload[0:2], 1)
	binary.LittleEndian.PutUint16(payload[2:4], 1)

	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
		Payload: payload,
	}, nil
}

// parsePCCCFileType converts a config string to a pccc.FileType.
func parsePCCCFileType(s string) (pccc.FileType, error) {
	switch s {
	case "O", "output":
		return pccc.FileTypeOutput, nil
	case "I", "input":
		return pccc.FileTypeInput, nil
	case "S", "status":
		return pccc.FileTypeStatus, nil
	case "B", "bit":
		return pccc.FileTypeBit, nil
	case "T", "timer":
		return pccc.FileTypeTimer, nil
	case "C", "counter":
		return pccc.FileTypeCounter, nil
	case "R", "control":
		return pccc.FileTypeControl, nil
	case "N", "integer":
		return pccc.FileTypeInteger, nil
	case "F", "float":
		return pccc.FileTypeFloat, nil
	case "ST", "string":
		return pccc.FileTypeString, nil
	case "A", "ascii":
		return pccc.FileTypeASCII, nil
	case "L", "long":
		return pccc.FileTypeLong, nil
	default:
		return 0, fmt.Errorf("unknown PCCC file type %q", s)
	}
}
