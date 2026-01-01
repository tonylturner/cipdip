package scenario

import (
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/tturner/cipdip/internal/cipclient"
	"github.com/tturner/cipdip/internal/config"
)

func parseHexPayload(input string) ([]byte, error) {
	cleaned := strings.ReplaceAll(strings.TrimSpace(input), " ", "")
	cleaned = strings.TrimPrefix(cleaned, "0x")
	if cleaned == "" {
		return nil, nil
	}
	if len(cleaned)%2 != 0 {
		return nil, fmt.Errorf("hex payload must have even length")
	}
	decoded := make([]byte, len(cleaned)/2)
	if _, err := hex.Decode(decoded, []byte(cleaned)); err != nil {
		return nil, fmt.Errorf("decode hex payload: %w", err)
	}
	return decoded, nil
}

func serviceCodeForTarget(service config.ServiceType, serviceCode uint8) (cipclient.CIPServiceCode, error) {
	switch service {
	case config.ServiceGetAttributeSingle:
		return cipclient.CIPServiceGetAttributeSingle, nil
	case config.ServiceSetAttributeSingle:
		return cipclient.CIPServiceSetAttributeSingle, nil
	case config.ServiceCustom:
		if serviceCode == 0 {
			return 0, fmt.Errorf("custom service requires service_code")
		}
		return cipclient.CIPServiceCode(serviceCode), nil
	default:
		return 0, fmt.Errorf("unsupported service type: %s", service)
	}
}

func classifyOutcome(err error, status uint8) string {
	if err != nil {
		msg := strings.ToLower(err.Error())
		if strings.Contains(msg, "timeout") {
			return "timeout"
		}
		return "error"
	}
	if status == 0 {
		return "success"
	}
	return "error"
}

func computeJitterMs(last *time.Time, expected time.Duration) float64 {
	now := time.Now()
	if last == nil {
		return 0
	}
	if last.IsZero() {
		*last = now
		return 0
	}
	elapsed := now.Sub(*last)
	*last = now
	jitter := elapsed - expected
	if jitter < 0 {
		jitter = -jitter
	}
	return float64(jitter.Milliseconds())
}
