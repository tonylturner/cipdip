package server

// Logix personality - tag-style interface (ControlLogix-like)

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
	"github.com/tturner/cipdip/internal/logging"
)

// LogixPersonality implements logix-like behavior
type LogixPersonality struct {
	config  *config.ServerConfig
	logger  *logging.Logger
	tags    map[string]*Tag
	mu      sync.RWMutex
}

// Tag represents a logix tag
type Tag struct {
	Config     config.LogixTagConfig
	Data       []byte
	Counter    uint32
	SinePhase  float64
	LastUpdate time.Time
	mu         sync.RWMutex
}

// NewLogixPersonality creates a new logix personality
func NewLogixPersonality(cfg *config.ServerConfig, logger *logging.Logger) (*LogixPersonality, error) {
	lp := &LogixPersonality{
		config: cfg,
		logger: logger,
		tags:   make(map[string]*Tag),
	}

	// Initialize tags
	for _, tagCfg := range cfg.LogixTags {
		tag := &Tag{
			Config:     tagCfg,
			Counter:    0,
			SinePhase:  0.0,
			LastUpdate: time.Now(),
		}

		// Calculate data size based on type
		elementSize := getTagTypeSize(tagCfg.Type)
		tag.Data = make([]byte, elementSize*int(tagCfg.ArrayLength))

		// Initialize data
		switch tagCfg.UpdatePattern {
		case "static":
			// Fill with zeros
		case "counter":
			// Initialize counter
			if elementSize == 4 && tagCfg.ArrayLength > 0 {
				binary.BigEndian.PutUint32(tag.Data[0:4], 0)
			}
		case "random":
			rand.Seed(time.Now().UnixNano())
			rand.Read(tag.Data)
		}

		lp.tags[tagCfg.Name] = tag
	}

	return lp, nil
}

// GetName returns the personality name
func (lp *LogixPersonality) GetName() string {
	return "logix_like"
}

// HandleCIPRequest handles a CIP request
func (lp *LogixPersonality) HandleCIPRequest(ctx context.Context, req cipclient.CIPRequest) (cipclient.CIPResponse, error) {
	// For logix-like, we'll use a simplified tag lookup
	// In a full implementation, this would parse tag names from the path
	// For now, we'll support Get_Attribute_Single on a generic tag structure

	switch req.Service {
	case cipclient.CIPServiceGetAttributeSingle:
		// Find a tag (simplified - use first tag for now)
		lp.mu.RLock()
		var tag *Tag
		for _, t := range lp.tags {
			tag = t
			break
		}
		lp.mu.RUnlock()

		if tag == nil {
			return cipclient.CIPResponse{
				Service: req.Service,
				Status:  0x01, // General error
			}, fmt.Errorf("no tags configured")
		}

		return lp.handleGetAttributeSingle(tag, req)

	case cipclient.CIPServiceSetAttributeSingle:
		// Find a tag
		lp.mu.RLock()
		var tag *Tag
		for _, t := range lp.tags {
			tag = t
			break
		}
		lp.mu.RUnlock()

		if tag == nil {
			return cipclient.CIPResponse{
				Service: req.Service,
				Status:  0x01,
			}, fmt.Errorf("no tags configured")
		}

		return lp.handleSetAttributeSingle(tag, req)

	default:
		return cipclient.CIPResponse{
			Service: req.Service,
			Status:  0x08, // Service not supported
		}, fmt.Errorf("unsupported service: 0x%02X", req.Service)
	}
}

// handleGetAttributeSingle handles Get_Attribute_Single
func (lp *LogixPersonality) handleGetAttributeSingle(tag *Tag, req cipclient.CIPRequest) (cipclient.CIPResponse, error) {
	tag.mu.Lock()
	defer tag.mu.Unlock()

	// Update data based on pattern
	now := time.Now()
	if now.Sub(tag.LastUpdate) > 100*time.Millisecond {
		lp.updateTagData(tag)
		tag.LastUpdate = now
	}

	return cipclient.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
		Payload: tag.Data,
	}, nil
}

// handleSetAttributeSingle handles Set_Attribute_Single
func (lp *LogixPersonality) handleSetAttributeSingle(tag *Tag, req cipclient.CIPRequest) (cipclient.CIPResponse, error) {
	tag.mu.Lock()
	defer tag.mu.Unlock()

	// Update data
	if len(req.Payload) > 0 {
		copyLen := len(req.Payload)
		if copyLen > len(tag.Data) {
			copyLen = len(tag.Data)
		}
		copy(tag.Data[:copyLen], req.Payload[:copyLen])
	}

	return cipclient.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
	}, nil
}

// updateTagData updates tag data based on pattern
func (lp *LogixPersonality) updateTagData(tag *Tag) {
	elementSize := getTagTypeSize(tag.Config.Type)

	switch tag.Config.UpdatePattern {
	case "counter":
		tag.Counter++
		if elementSize == 4 && len(tag.Data) >= 4 {
			binary.BigEndian.PutUint32(tag.Data[0:4], tag.Counter)
		}

	case "sine":
		tag.SinePhase += 0.1
		if tag.SinePhase > 2*math.Pi {
			tag.SinePhase -= 2 * math.Pi
		}
		if elementSize == 4 && len(tag.Data) >= 4 {
			val := math.Sin(tag.SinePhase)
			binary.BigEndian.PutUint32(tag.Data[0:4], math.Float32bits(float32(val)))
		}

	case "sawtooth":
		tag.Counter++
		if tag.Counter > 100 {
			tag.Counter = 0
		}
		if elementSize == 4 && len(tag.Data) >= 4 {
			binary.BigEndian.PutUint32(tag.Data[0:4], tag.Counter)
		}

	case "random":
		rand.Read(tag.Data)

	case "static":
		// No update
	}
}

// getTagTypeSize returns the size in bytes for a tag type
func getTagTypeSize(tagType string) int {
	switch tagType {
	case "BOOL":
		return 1
	case "SINT":
		return 1
	case "INT":
		return 2
	case "DINT":
		return 4
	case "REAL":
		return 4
	case "LINT":
		return 8
	case "LREAL":
		return 8
	default:
		return 4 // Default to DINT size
	}
}
