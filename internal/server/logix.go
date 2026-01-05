package server

// Logix personality - tag-style interface (ControlLogix-like)

import (
	"context"
	"encoding/binary"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
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
	config *config.ServerConfig
	logger *logging.Logger
	tags   map[string]*Tag
	rng    *rand.Rand
	mu     sync.RWMutex
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
	seed := cfg.Server.RNGSeed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	lp := &LogixPersonality{
		config: cfg,
		logger: logger,
		tags:   make(map[string]*Tag),
		rng:    rand.New(rand.NewSource(seed)),
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
				order := cipclient.CurrentProtocolProfile().CIPByteOrder
				order.PutUint32(tag.Data[0:4], 0)
			}
		case "random":
			lp.rng.Read(tag.Data)
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
func (lp *LogixPersonality) HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	// For logix-like, we'll use a simplified tag lookup
	// In a full implementation, this would parse tag names from the path
	// For now, we'll support Get_Attribute_Single on a generic tag structure

	switch req.Service {
	case protocol.CIPServiceExecutePCCC:
		if req.Path.Class != 0 && req.Path.Class != 0x0067 && req.Path.Class != 0x00A1 {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x08, // Service not supported
			}, fmt.Errorf("Execute_PCCC unsupported for class 0x%04X", req.Path.Class)
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, nil

	case protocol.CIPServiceReadTag:
		tag, err := lp.tagForRequest(req)
		if err != nil {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x05,
			}, err
		}
		return lp.handleReadTag(tag, req)

	case protocol.CIPServiceReadTagFragmented:
		tag, err := lp.tagForRequest(req)
		if err != nil {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x05,
			}, err
		}
		return lp.handleReadTagFragmented(tag, req)

	case protocol.CIPServiceWriteTag:
		tag, err := lp.tagForRequest(req)
		if err != nil {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x05,
			}, err
		}
		return lp.handleWriteTag(tag, req)

	case protocol.CIPServiceWriteTagFragmented:
		tag, err := lp.tagForRequest(req)
		if err != nil {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x05,
			}, err
		}
		return lp.handleWriteTagFragmented(tag, req)

	case protocol.CIPServiceCode(0x51):
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}, nil

	case protocol.CIPServiceGetAttributeSingle:
		tag, err := lp.tagForRequest(req)
		if err != nil {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x01, // General error
			}, err
		}

		return lp.handleGetAttributeSingle(tag, req)

	case protocol.CIPServiceSetAttributeSingle:
		tag, err := lp.tagForRequest(req)
		if err != nil {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x01,
			}, err
		}

		return lp.handleSetAttributeSingle(tag, req)

	default:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08, // Service not supported
		}, fmt.Errorf("unsupported service: 0x%02X (%s)", uint8(req.Service), req.Service)
	}
}

func (lp *LogixPersonality) firstTag() *Tag {
	lp.mu.RLock()
	defer lp.mu.RUnlock()
	for _, t := range lp.tags {
		return t
	}
	return nil
}

func (lp *LogixPersonality) findTag(name string) *Tag {
	lp.mu.RLock()
	defer lp.mu.RUnlock()
	return lp.tags[name]
}

func (lp *LogixPersonality) tagForRequest(req protocol.CIPRequest) (*Tag, error) {
	if req.Path.Name != "" {
		tag := lp.findTag(req.Path.Name)
		if tag == nil {
			return nil, fmt.Errorf("tag not found: %s", req.Path.Name)
		}
		return tag, nil
	}
	tag := lp.firstTag()
	if tag == nil {
		return nil, fmt.Errorf("no tags configured")
	}
	return tag, nil
}

// handleGetAttributeSingle handles Get_Attribute_Single
func (lp *LogixPersonality) handleGetAttributeSingle(tag *Tag, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	tag.mu.Lock()
	defer tag.mu.Unlock()

	// Update data based on pattern
	now := time.Now()
	if now.Sub(tag.LastUpdate) > 100*time.Millisecond {
		lp.updateTagData(tag)
		tag.LastUpdate = now
	}

	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
		Payload: tag.Data,
	}, nil
}

// handleReadTag handles Read_Tag (0x4C).
func (lp *LogixPersonality) handleReadTag(tag *Tag, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	tag.mu.Lock()
	defer tag.mu.Unlock()

	now := time.Now()
	if now.Sub(tag.LastUpdate) > 100*time.Millisecond {
		lp.updateTagData(tag)
		tag.LastUpdate = now
	}

	elementSize := getTagTypeSize(tag.Config.Type)
	maxElements := 1
	if tag.Config.ArrayLength > 0 {
		maxElements = int(tag.Config.ArrayLength)
	}

	elementCount := uint16(1)
	if len(req.Payload) >= 2 {
		elementCount = binary.LittleEndian.Uint16(req.Payload[0:2])
		if elementCount == 0 {
			elementCount = 1
		}
	}
	if int(elementCount) > maxElements {
		elementCount = uint16(maxElements)
	}

	dataLen := int(elementCount) * elementSize
	if dataLen > len(tag.Data) {
		dataLen = len(tag.Data)
	}

	payload := make([]byte, 4+dataLen)
	binary.LittleEndian.PutUint16(payload[0:2], uint16(protocol.CIPTypeCode(tag.Config.Type)))
	binary.LittleEndian.PutUint16(payload[2:4], elementCount)
	copy(payload[4:], tag.Data[:dataLen])

	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
		Payload: payload,
	}, nil
}

func (lp *LogixPersonality) handleReadTagFragmented(tag *Tag, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	tag.mu.Lock()
	defer tag.mu.Unlock()

	now := time.Now()
	if now.Sub(tag.LastUpdate) > 100*time.Millisecond {
		lp.updateTagData(tag)
		tag.LastUpdate = now
	}

	elementSize := getTagTypeSize(tag.Config.Type)
	maxElements := 1
	if tag.Config.ArrayLength > 0 {
		maxElements = int(tag.Config.ArrayLength)
	}

	if len(req.Payload) < 6 {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x13,
			Path:    req.Path,
		}, fmt.Errorf("read tag fragmented payload too short")
	}

	elementCount := binary.LittleEndian.Uint16(req.Payload[0:2])
	if elementCount == 0 {
		elementCount = 1
	}
	if int(elementCount) > maxElements {
		elementCount = uint16(maxElements)
	}
	byteOffset := binary.LittleEndian.Uint32(req.Payload[2:6])

	dataLen := int(elementCount) * elementSize
	if dataLen > len(tag.Data) {
		dataLen = len(tag.Data)
	}
	if int(byteOffset) > dataLen {
		byteOffset = uint32(dataLen)
	}

	remaining := dataLen - int(byteOffset)
	if remaining < 0 {
		remaining = 0
	}
	chunkLen := remaining
	if chunkLen > 480 {
		chunkLen = 480
	}

	payload := make([]byte, 4+chunkLen)
	binary.LittleEndian.PutUint16(payload[0:2], uint16(protocol.CIPTypeCode(tag.Config.Type)))
	binary.LittleEndian.PutUint16(payload[2:4], elementCount)
	if chunkLen > 0 {
		copy(payload[4:], tag.Data[int(byteOffset):int(byteOffset)+chunkLen])
	}

	status := uint8(0x00)
	if int(byteOffset)+chunkLen < dataLen {
		status = 0x06 // Reply data too large (more fragments expected)
	}

	return protocol.CIPResponse{
		Service: req.Service,
		Status:  status,
		Path:    req.Path,
		Payload: payload,
	}, nil
}

// handleWriteTag handles Write_Tag (0x4D).
func (lp *LogixPersonality) handleWriteTag(tag *Tag, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	tag.mu.Lock()
	defer tag.mu.Unlock()

	if len(req.Payload) < 4 {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x13, // Not enough data
			Path:    req.Path,
		}, fmt.Errorf("write tag payload too short")
	}

	data := req.Payload[4:]
	copyLen := len(data)
	if copyLen > len(tag.Data) {
		copyLen = len(tag.Data)
	}
	if copyLen > 0 {
		copy(tag.Data[:copyLen], data[:copyLen])
	}

	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
	}, nil
}

func (lp *LogixPersonality) handleWriteTagFragmented(tag *Tag, req protocol.CIPRequest) (protocol.CIPResponse, error) {
	tag.mu.Lock()
	defer tag.mu.Unlock()

	if len(req.Payload) < 8 {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x13,
			Path:    req.Path,
		}, fmt.Errorf("write tag fragmented payload too short")
	}

	byteOffset := binary.LittleEndian.Uint32(req.Payload[4:8])
	typeCode := binary.LittleEndian.Uint16(req.Payload[0:2])
	if protocol.CIPDataType(typeCode) != protocol.CIPTypeCode(tag.Config.Type) {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x13,
			Path:    req.Path,
		}, fmt.Errorf("write tag fragmented type mismatch: got %s", protocol.CIPTypeName(protocol.CIPDataType(typeCode)))
	}
	data := req.Payload[8:]
	if int(byteOffset) >= len(tag.Data) {
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x05,
			Path:    req.Path,
		}, fmt.Errorf("write offset out of range")
	}

	copyLen := len(data)
	if int(byteOffset)+copyLen > len(tag.Data) {
		copyLen = len(tag.Data) - int(byteOffset)
	}
	if copyLen > 0 {
		copy(tag.Data[int(byteOffset):int(byteOffset)+copyLen], data[:copyLen])
	}

	return protocol.CIPResponse{
		Service: req.Service,
		Status:  0x00,
		Path:    req.Path,
	}, nil
}

// handleSetAttributeSingle handles Set_Attribute_Single
func (lp *LogixPersonality) handleSetAttributeSingle(tag *Tag, req protocol.CIPRequest) (protocol.CIPResponse, error) {
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

	return protocol.CIPResponse{
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
			order := cipclient.CurrentProtocolProfile().CIPByteOrder
			order.PutUint32(tag.Data[0:4], tag.Counter)
		}

	case "sine":
		tag.SinePhase += 0.1
		if tag.SinePhase > 2*math.Pi {
			tag.SinePhase -= 2 * math.Pi
		}
		if elementSize == 4 && len(tag.Data) >= 4 {
			val := math.Sin(tag.SinePhase)
			order := cipclient.CurrentProtocolProfile().CIPByteOrder
			order.PutUint32(tag.Data[0:4], math.Float32bits(float32(val)))
		}

	case "sawtooth":
		tag.Counter++
		if tag.Counter > 100 {
			tag.Counter = 0
		}
		if elementSize == 4 && len(tag.Data) >= 4 {
			order := cipclient.CurrentProtocolProfile().CIPByteOrder
			order.PutUint32(tag.Data[0:4], tag.Counter)
		}

	case "random":
		lp.rng.Read(tag.Data)

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
