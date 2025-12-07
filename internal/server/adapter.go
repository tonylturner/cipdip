package server

// Adapter personality - assembly-style object model (CLICK-like)

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
)

// AdapterPersonality implements adapter-style behavior
type AdapterPersonality struct {
	config  *config.ServerConfig
	logger  *logging.Logger
	assemblies map[string]*Assembly
	mu       sync.RWMutex
}

// Assembly represents an adapter assembly
type Assembly struct {
	Config      config.AdapterAssemblyConfig
	Data        []byte
	Counter     uint32
	LastUpdate  time.Time
	mu          sync.RWMutex
}

// NewAdapterPersonality creates a new adapter personality
func NewAdapterPersonality(cfg *config.ServerConfig, logger *logging.Logger) (*AdapterPersonality, error) {
	ap := &AdapterPersonality{
		config:     cfg,
		logger:     logger,
		assemblies: make(map[string]*Assembly),
	}

	// Initialize assemblies
	for _, asmCfg := range cfg.AdapterAssemblies {
		asm := &Assembly{
			Config:     asmCfg,
			Data:       make([]byte, asmCfg.SizeBytes),
			Counter:    0,
			LastUpdate: time.Now(),
		}

		// Initialize data based on pattern
		switch asmCfg.UpdatePattern {
		case "static":
			// Fill with zeros or pattern
			for i := range asm.Data {
				asm.Data[i] = 0x00
			}
		case "random":
			rand.Seed(time.Now().UnixNano())
			rand.Read(asm.Data)
		case "counter":
			// Initialize counter in first bytes
			binary.BigEndian.PutUint32(asm.Data[0:4], 0)
		}

		ap.assemblies[asmCfg.Name] = asm
	}

	return ap, nil
}

// GetName returns the personality name
func (ap *AdapterPersonality) GetName() string {
	return "adapter"
}

// HandleCIPRequest handles a CIP request
func (ap *AdapterPersonality) HandleCIPRequest(ctx context.Context, req cipclient.CIPRequest) (cipclient.CIPResponse, error) {
	// Find matching assembly
	var assembly *Assembly
	ap.mu.RLock()
	for _, asm := range ap.assemblies {
		if asm.Config.Class == req.Path.Class &&
			asm.Config.Instance == req.Path.Instance &&
			asm.Config.Attribute == req.Path.Attribute {
			assembly = asm
			break
		}
	}
	ap.mu.RUnlock()

	if assembly == nil {
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x01, // General error
		}, fmt.Errorf("assembly not found: class=0x%04X instance=0x%04X attribute=0x%02X",
			req.Path.Class, req.Path.Instance, req.Path.Attribute)
	}

	// Handle service
	switch req.Service {
	case cipclient.CIPServiceGetAttributeSingle:
		return ap.handleGetAttributeSingle(assembly, req)

	case cipclient.CIPServiceSetAttributeSingle:
		return ap.handleSetAttributeSingle(assembly, req)

	default:
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x08, // Service not supported
		}, fmt.Errorf("unsupported service: 0x%02X (%s)", uint8(req.Service), req.Service)
	}
}

// handleGetAttributeSingle handles Get_Attribute_Single
func (ap *AdapterPersonality) handleGetAttributeSingle(asm *Assembly, req cipclient.CIPRequest) (cipclient.CIPResponse, error) {
	asm.mu.Lock()
	defer asm.mu.Unlock()

	// Update data based on pattern
	now := time.Now()
	if now.Sub(asm.LastUpdate) > 100*time.Millisecond {
		ap.updateAssemblyData(asm)
		asm.LastUpdate = now
	}

	// Return assembly data
	return cipclient.CIPResponse{
		Service: req.Service,
		Status:  0x00, // Success
		Path:    req.Path,
		Payload: asm.Data,
	}, nil
}

// handleSetAttributeSingle handles Set_Attribute_Single
func (ap *AdapterPersonality) handleSetAttributeSingle(asm *Assembly, req cipclient.CIPRequest) (cipclient.CIPResponse, error) {
	if !asm.Config.Writable {
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x05, // Attribute not settable
		}, fmt.Errorf("assembly %s is not writable", asm.Config.Name)
	}

	asm.mu.Lock()
	defer asm.mu.Unlock()

	// Update data
	if len(req.Payload) > 0 {
		copyLen := len(req.Payload)
		if copyLen > len(asm.Data) {
			copyLen = len(asm.Data)
		}
		copy(asm.Data[:copyLen], req.Payload[:copyLen])
	}

	// Handle reflect_inputs pattern
	if asm.Config.UpdatePattern == "reflect_inputs" {
		// Data is already set, just acknowledge
	}

	return cipclient.CIPResponse{
		Service: req.Service,
		Status:  0x00, // Success
		Path:    req.Path,
	}, nil
}

// updateAssemblyData updates assembly data based on pattern
func (ap *AdapterPersonality) updateAssemblyData(asm *Assembly) {
	switch asm.Config.UpdatePattern {
	case "counter":
		asm.Counter++
		if len(asm.Data) >= 4 {
			binary.BigEndian.PutUint32(asm.Data[0:4], asm.Counter)
		}

	case "random":
		rand.Read(asm.Data)

	case "static":
		// No update needed

	case "reflect_inputs":
		// No update needed (set by SetAttribute)
	}
}
