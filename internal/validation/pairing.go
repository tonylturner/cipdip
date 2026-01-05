package validation

import (
	"fmt"
	"strings"
)

// BuildPairingResults builds request/response pairing results for manifest-driven PCAPs.
func BuildPairingResults(manifest ValidationManifest, results []ValidateResult) map[string]*PairingResult {
	type idx struct {
		req int
		resp int
	}
	indexes := map[string]idx{}
	for i, pkt := range manifest.Packets {
		base := strings.TrimSuffix(strings.TrimSuffix(pkt.ID, "/request"), "/response")
		entry := indexes[base]
		if strings.HasSuffix(pkt.ID, "/request") {
			entry.req = i
		} else if strings.HasSuffix(pkt.ID, "/response") {
			entry.resp = i
		}
		indexes[base] = entry
	}

	out := map[string]*PairingResult{}
	for base, entry := range indexes {
		result := &PairingResult{
			BaseID:        base,
			RequestIndex:  entry.req + 1,
			ResponseIndex: entry.resp + 1,
		}
		hasReq := entry.req >= 0 && entry.req < len(results) && strings.HasSuffix(manifest.Packets[entry.req].ID, "/request")
		hasResp := entry.resp >= 0 && entry.resp < len(results) && strings.HasSuffix(manifest.Packets[entry.resp].ID, "/response")
		result.Required = hasReq && hasResp

		if !result.Required {
			out[base] = result
			continue
		}

		req := results[entry.req]
		resp := results[entry.resp]
		if strings.EqualFold(manifest.Packets[entry.req].TrafficMode, "client_only") {
			result.Required = false
			result.Pass = true
			result.Reason = "pairing_skipped_client_only"
			out[base] = result
			continue
		}
		if req.Internal == nil || resp.Internal == nil {
			result.Required = false
			result.Pass = true
			result.Reason = "pairing_skipped_missing_internal"
			out[base] = result
			continue
		}
		result.OrderOK = entry.resp > entry.req

		sessionMatch := false
		serviceMatch := false
		statusPresent := false
		tupleMatch := false

		if req.Internal != nil && resp.Internal != nil {
			sessionMatch = req.Internal.ENIPSession != 0 && req.Internal.ENIPSession == resp.Internal.ENIPSession
			tupleMatch = req.Internal.Transport != "" &&
				req.Internal.Transport == resp.Internal.Transport &&
				req.Internal.SrcIP == resp.Internal.DstIP &&
				req.Internal.DstIP == resp.Internal.SrcIP &&
				req.Internal.SrcPort == resp.Internal.DstPort &&
				req.Internal.DstPort == resp.Internal.SrcPort
			if req.Internal.CIPService != 0 && resp.Internal.CIPService != 0 {
				serviceMatch = resp.Internal.CIPService == (req.Internal.CIPService|0x80)
			}
			statusPresent = resp.Internal.CIPStatusPresent
		}

		result.SessionMatch = sessionMatch
		result.TupleMatch = tupleMatch
		result.ServiceMatch = serviceMatch
		result.StatusPresent = statusPresent

		failures := []string{}
		if !result.OrderOK {
			failures = append(failures, "response_before_request")
		}
		if !sessionMatch {
			failures = append(failures, "session_mismatch")
		}
		if !tupleMatch {
			failures = append(failures, "tuple_mismatch")
		}
		if !serviceMatch {
			failures = append(failures, "service_mismatch")
		}
		if !statusPresent {
			failures = append(failures, "status_missing")
		}

		if len(failures) == 0 {
			result.Pass = true
		} else {
			result.Pass = false
			result.Reason = fmt.Sprintf("pairing_failed=%s", strings.Join(failures, ","))
		}

		out[base] = result
	}

	return out
}
