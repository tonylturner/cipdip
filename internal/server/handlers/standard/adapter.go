package standard

// Adapter personality - assembly-style object model (CLICK-like)

import (
	"context"
	"fmt"
	"github.com/tonylturner/cipdip/internal/cip/spec"
	"math/rand"
	"sync"
	"time"

	cipclient "github.com/tonylturner/cipdip/internal/cip/client"
	"github.com/tonylturner/cipdip/internal/cip/codec"
	"github.com/tonylturner/cipdip/internal/cip/protocol"
	"github.com/tonylturner/cipdip/internal/config"
	"github.com/tonylturner/cipdip/internal/logging"
)

// AdapterPersonality implements adapter-style behavior
type AdapterPersonality struct {
	config     *config.ServerConfig
	logger     *logging.Logger
	assemblies map[string]*Assembly
	rng        *rand.Rand
	mu         sync.RWMutex
}

// Assembly represents an adapter assembly
type Assembly struct {
	Config     config.AdapterAssemblyConfig
	Data       []byte
	Counter    uint32
	LastUpdate time.Time
	mu         sync.RWMutex
}

// NewAdapterPersonality creates a new adapter personality
func NewAdapterPersonality(cfg *config.ServerConfig, logger *logging.Logger) (*AdapterPersonality, error) {
	seed := cfg.Server.RNGSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	ap := &AdapterPersonality{
		config:     cfg,
		logger:     logger,
		assemblies: make(map[string]*Assembly),
		rng:        rand.New(rand.NewSource(seed)),
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
			ap.rng.Read(asm.Data)
		case "counter":
			// Initialize counter in first bytes
			order := cipclient.CurrentProtocolProfile().CIPByteOrder
			codec.PutUint32(order, asm.Data[0:4], 0)
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
func (ap *AdapterPersonality) HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error) {
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
		return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x01, // General error
			}, fmt.Errorf("assembly not found: class=0x%04X instance=0x%04X attribute=0x%02X",
				req.Path.Class, req.Path.Instance, req.Path.Attribute)
	}

	// Handle service
	switch req.Service {
	case spec.CIPServiceGetAttributeSingle:
		return ap.handleGetAttributeSingle(assembly, req)

	case spec.CIPServiceSetAttributeSingle:
		return ap.handleSetAttributeSingle(assembly, req)

	default:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08, // Service not supported
		}, fmt.Errorf("unsupported service: 0x%02X (%s)", uint8(req.Service), spec.ServiceName(req.Service))
	}
}

// handleGetAttributeSingle handles Get_Attribute_Single
func (ap *AdapterPersonality) handleGetAttributeSingle(asm *Assembly, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	asm.mu.Lock()
	defer asm.mu.Unlock()

	// Update data based on pattern
	now := time.Now()
	if now.Sub(asm.LastUpdate) > 100*time.Millisecond {
		ap.updateAssemblyData(asm)
		asm.LastUpdate = now
	}

	// Return assembly data
	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00, // Success
		Path:    req.Path,
		Payload: asm.Data,
	}, nil
}

// handleSetAttributeSingle handles Set_Attribute_Single
func (ap *AdapterPersonality) handleSetAttributeSingle(asm *Assembly, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	if !asm.Config.Writable {
		return protocol.CIPResponse{
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

	return protocol.CIPResponse{
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
			order := cipclient.CurrentProtocolProfile().CIPByteOrder
			codec.PutUint32(order, asm.Data[0:4], asm.Counter)
		}

	case "random":
		ap.rng.Read(asm.Data)

	case "static":
		// No update needed

	case "reflect_inputs":
		// No update needed (set by SetAttribute)
	}
}
