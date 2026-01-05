package standard

import (
	"context"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
	"github.com/tturner/cipdip/internal/cip/codec"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
)

type GenericObjectHandler struct {
	store          *genericAttributeStore
	profileClasses map[uint16]struct{}
}

func NewGenericObjectHandler(profileClasses map[uint16]struct{}) *GenericObjectHandler {
	return &GenericObjectHandler{
		store:          newGenericAttributeStore(),
		profileClasses: profileClasses,
	}
}

func (h *GenericObjectHandler) HandleCIPRequest(ctx context.Context, req protocol.CIPRequest) (protocol.CIPResponse, bool, error) {
	if !h.isGenericClass(req.Path.Class) {
		return protocol.CIPResponse{}, false, nil
	}

	switch req.Service {
	case spec.CIPServiceExecutePCCC,
		spec.CIPServiceReadTag,
		spec.CIPServiceWriteTag,
		spec.CIPServiceReadModifyWrite,
		spec.CIPServiceUploadTransfer,
		spec.CIPServiceDownloadTransfer,
		spec.CIPServiceClearFile:
		if isEnergyBaseClass(req.Path.Class) && (req.Service == spec.CIPServiceExecutePCCC || req.Service == spec.CIPServiceReadTag) {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x00,
				Path:    req.Path,
			}, true, nil
		}
		if isFileObjectClass(req.Path.Class) || isSymbolicClass(req.Path.Class) || isModbusClass(req.Path.Class) || isMotionAxisClass(req.Path.Class) || isSafetyClass(req.Path.Class) {
			return protocol.CIPResponse{
				Service: req.Service,
				Status:  0x00,
				Path:    req.Path,
			}, true, nil
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}, true, nil

	case spec.CIPServiceGetAttributeSingle:
		payload, ok := h.store.get(req.Path.Class, req.Path.Instance, req.Path.Attribute)
		if !ok {
			payload = []byte{0x00}
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true, nil

	case spec.CIPServiceSetAttributeSingle:
		h.store.set(req.Path.Class, req.Path.Instance, req.Path.Attribute, req.Payload)
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true, nil

	case spec.CIPServiceGetAttributeAll:
		attrs := h.store.listAttributes(req.Path.Class, req.Path.Instance)
		payload := flattenAttributes(attrs)
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
			Payload: payload,
		}, true, nil

	case spec.CIPServiceSetAttributeList:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true, nil

	case spec.CIPServiceGetAttributeList:
		payload, ok := buildAttributeListResponse(req, h.store)
		status := uint8(0x00)
		if !ok {
			status = 0x13
		}
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  status,
			Path:    req.Path,
			Payload: payload,
		}, true, nil

	case spec.CIPServiceReset:
		h.store.clearInstance(req.Path.Class, req.Path.Instance)
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true, nil

	case spec.CIPServiceStart,
		spec.CIPServiceStop,
		spec.CIPServiceCreate,
		spec.CIPServiceDelete,
		spec.CIPServiceRestore,
		spec.CIPServiceSave,
		spec.CIPServiceGetMember,
		spec.CIPServiceSetMember,
		spec.CIPServiceInsertMember,
		spec.CIPServiceRemoveMember,
		spec.CIPServiceReadTagFragmented,
		spec.CIPServiceForwardOpen:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x00,
			Path:    req.Path,
		}, true, nil

	default:
		return protocol.CIPResponse{
			Service: req.Service,
			Status:  0x08,
			Path:    req.Path,
		}, true, nil
	}
}

func (h *GenericObjectHandler) isGenericClass(class uint16) bool {
	if _, ok := h.profileClasses[class]; ok {
		return true
	}
	switch class {
	case 0x0066, 0x00F4, 0x00F5, 0x0100, 0x00F6, 0x3700, 0x0002, 0x0064, 0x00AC, 0x008E, 0x1A00, 0x0004, 0x0005, 0x0006:
		return true
	case spec.CIPClassFileObject,
		spec.CIPClassSymbolObject,
		spec.CIPClassTemplateObject,
		spec.CIPClassEventLog,
		spec.CIPClassTimeSync,
		spec.CIPClassModbus:
		return true
	default:
		return false
	}
}

type genericAttributeStore struct {
	mu     sync.RWMutex
	values map[string][]byte
}

func newGenericAttributeStore() *genericAttributeStore {
	return &genericAttributeStore{
		values: make(map[string][]byte),
	}
}

func (s *genericAttributeStore) get(class, instance, attribute uint16) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value, ok := s.values[genericKey(class, instance, attribute)]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(value))
	copy(out, value)
	return out, true
}

func (s *genericAttributeStore) set(class, instance, attribute uint16, value []byte) {
	if value == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clone := make([]byte, len(value))
	copy(clone, value)
	s.values[genericKey(class, instance, attribute)] = clone
}

func (s *genericAttributeStore) listAttributes(class, instance uint16) map[uint16][]byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	attrs := make(map[uint16][]byte)
	for key, value := range s.values {
		parsedClass, parsedInstance, parsedAttr, ok := parseGenericKey(key)
		if !ok {
			continue
		}
		if parsedClass != class || parsedInstance != instance {
			continue
		}
		clone := make([]byte, len(value))
		copy(clone, value)
		attrs[parsedAttr] = clone
	}
	return attrs
}

func (s *genericAttributeStore) clearInstance(class, instance uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key := range s.values {
		parsedClass, parsedInstance, _, ok := parseGenericKey(key)
		if !ok {
			continue
		}
		if parsedClass == class && parsedInstance == instance {
			delete(s.values, key)
		}
	}
}

func genericKey(class, instance, attribute uint16) string {
	return fmt.Sprintf("%04X:%04X:%04X", class, instance, attribute)
}

func parseGenericKey(key string) (uint16, uint16, uint16, bool) {
	var class, instance, attribute uint16
	_, err := fmt.Sscanf(key, "%04X:%04X:%04X", &class, &instance, &attribute)
	return class, instance, attribute, err == nil
}

func isEnergyBaseClass(class uint16) bool {
	return class == spec.CIPClassEnergyBase
}

func isFileObjectClass(class uint16) bool {
	return class == spec.CIPClassFileObject
}

func isSymbolicClass(class uint16) bool {
	return class == spec.CIPClassSymbolObject || class == spec.CIPClassTemplateObject
}

func isModbusClass(class uint16) bool {
	return class == spec.CIPClassModbus
}

func isMotionAxisClass(class uint16) bool {
	return class == spec.CIPClassMotionAxis
}

func isSafetyClass(class uint16) bool {
	return class == spec.CIPClassSafetySupervisor || class == spec.CIPClassSafetyValidator
}

func flattenAttributes(attrs map[uint16][]byte) []byte {
	if len(attrs) == 0 {
		return nil
	}
	keys := make([]uint16, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })

	payload := make([]byte, 0)
	for _, key := range keys {
		payload = append(payload, attrs[key]...)
	}
	return payload
}

func buildAttributeListResponse(req protocol.CIPRequest, store *genericAttributeStore) ([]byte, bool) {
	if len(req.Payload) < 2 {
		return nil, false
	}
	count := int(binary.LittleEndian.Uint16(req.Payload[:2]))
	offset := 2
	order := cipclient.CurrentProtocolProfile().CIPByteOrder
	payload := make([]byte, 0)
	for i := 0; i < count; i++ {
		if len(req.Payload) < offset+2 {
			return payload, false
		}
		attrID := order.Uint16(req.Payload[offset : offset+2])
		offset += 2

		value, ok := store.get(req.Path.Class, req.Path.Instance, attrID)
		payload = append(payload, 0x00, 0x00)
		codec.PutUint16(order, payload[len(payload)-2:], attrID)

		status := byte(0x00)
		if !ok {
			status = 0x14
		}
		payload = append(payload, status, 0x00)
		if ok {
			payload = append(payload, value...)
		}
	}
	return payload, true
}
