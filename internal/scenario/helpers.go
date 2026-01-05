package scenario

import (
	"encoding/hex"
	"fmt"
	"github.com/tturner/cipdip/internal/cip/protocol"
	"github.com/tturner/cipdip/internal/cip/spec"
	"strings"
	"time"

	cipclient "github.com/tturner/cipdip/internal/cip/client"
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

func applyTargetPayload(req protocol.CIPRequest, payloadType string, payloadParams map[string]any, payloadHex string) (protocol.CIPRequest, error) {
	if payloadHex != "" {
		payload, err := parseHexPayload(payloadHex)
		if err != nil {
			return req, err
		}
		req.Payload = payload
		return req, nil
	}
	if payloadType == "" && len(payloadParams) == 0 {
		return req, nil
	}
	result, err := cipclient.BuildServicePayload(req, cipclient.PayloadSpec{
		Type:   payloadType,
		Params: payloadParams,
	})
	if err != nil {
		return req, err
	}
	req.Payload = result.Payload
	if len(result.RawPath) > 0 {
		req.RawPath = result.RawPath
	}
	return req, nil
}

func serviceCodeForTarget(service config.ServiceType, serviceCode uint8) (protocol.CIPServiceCode, error) {
	switch service {
	case config.ServiceGetAttributeSingle:
		return spec.CIPServiceGetAttributeSingle, nil
	case config.ServiceSetAttributeSingle:
		return spec.CIPServiceSetAttributeSingle, nil
	case config.ServiceCustom:
		if serviceCode == 0 {
			return 0, fmt.Errorf("custom service requires service_code")
		}
		return protocol.CIPServiceCode(serviceCode), nil
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


