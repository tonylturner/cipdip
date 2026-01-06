package report

import "github.com/tturner/cipdip/internal/validation"

// ValidationReport captures per-PCAP validation results.
type ValidationReport struct {
	GeneratedAt      string       `json:"generated_at"`
	CIPDIPVersion    string       `json:"cipdip_version"`
	CIPDIPCommit     string       `json:"cipdip_commit"`
	CIPDIPDate       string       `json:"cipdip_date"`
	TsharkPath       string       `json:"tshark_path,omitempty"`
	TsharkVersion    string       `json:"tshark_version,omitempty"`
	ExpertPolicy     string       `json:"expert_policy,omitempty"`
	ConversationMode string       `json:"conversation_mode,omitempty"`
	Profile          string       `json:"profile,omitempty"`
	PCAPs            []PCAPReport `json:"pcaps"`
}

// PCAPReport captures per-pcap validation output.
type PCAPReport struct {
	PCAP         string                        `json:"pcap"`
	PacketCount  int                           `json:"packet_count"`
	Pass         bool                          `json:"pass"`
	InvalidCount int                           `json:"invalid_count"`
	Packets      []validation.PacketEvaluation `json:"packets,omitempty"`
}
