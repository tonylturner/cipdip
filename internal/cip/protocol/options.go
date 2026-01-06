package protocol

import (
	"encoding/binary"
	"sync"
)

// Options controls CIP Message Router framing.
type Options struct {
	ByteOrder           binary.ByteOrder
	IncludePathSize     bool
	IncludeRespReserved bool
}

var (
	optionsMu      sync.RWMutex
	currentOptions = Options{
		ByteOrder:           binary.LittleEndian,
		IncludePathSize:     true,
		IncludeRespReserved: true,
	}
)

// SetOptions sets the global CIP protocol options.
func SetOptions(opts Options) {
	optionsMu.Lock()
	defer optionsMu.Unlock()
	if opts.ByteOrder == nil {
		opts.ByteOrder = binary.LittleEndian
	}
	currentOptions = opts
}

// CurrentOptions returns the active CIP protocol options.
func CurrentOptions() Options {
	optionsMu.RLock()
	defer optionsMu.RUnlock()
	return currentOptions
}

func currentByteOrder() binary.ByteOrder {
	optionsMu.RLock()
	defer optionsMu.RUnlock()
	if currentOptions.ByteOrder == nil {
		return binary.LittleEndian
	}
	return currentOptions.ByteOrder
}
