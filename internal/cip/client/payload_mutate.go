package client

import (
	"math/rand"
	"time"
)

// PayloadMutation describes a deterministic payload mutation.
type PayloadMutation struct {
	Kind string
	Seed int64
}

// ApplyPayloadMutation returns a mutated payload for DPI robustness testing.
func ApplyPayloadMutation(payload []byte, mutation PayloadMutation) []byte {
	if len(payload) == 0 {
		return payload
	}
	seed := mutation.Seed
	if seed == 0 {
		seed = time.Now().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed))
	out := append([]byte(nil), payload...)
	switch mutation.Kind {
	case "missing_fields":
		if len(out) > 1 {
			return out[:len(out)/2]
		}
	case "wrong_length":
		out = append(out, 0xFF, 0xFF)
	case "invalid_offsets":
		if len(out) >= 6 {
			idx := len(out) - 4
			out[idx] = 0xFF
			out[idx+1] = 0xFF
			out[idx+2] = 0xFF
			out[idx+3] = 0xFF
		}
	case "wrong_datatype":
		if len(out) >= 2 {
			out[0] = 0xFF
			out[1] = 0xFF
		}
	case "flip_bits":
		pos := rng.Intn(len(out))
		out[pos] ^= 0xFF
	}
	return out
}

