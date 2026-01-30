package dhplus

import "testing"

func TestCheckPayload(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		wantDH   bool
	}{
		{
			name:   "valid_typed_read",
			data:   []byte{0x05, 0x01, 0x68, 0x00, 0x34, 0x12, 0x02, 0x07, 0x89, 0x00},
			wantDH: true,
		},
		{
			name:   "valid_diagnostic",
			data:   []byte{0x03, 0x01, 0x06, 0x00, 0x01, 0x00},
			wantDH: true,
		},
		{
			name:   "valid_unprotected_read",
			data:   []byte{0x0A, 0x02, 0x01, 0x00, 0x10, 0x00, 0x04, 0x07, 0x89, 0x00},
			wantDH: true,
		},
		{
			name:   "too_short",
			data:   []byte{0x01, 0x02, 0x03},
			wantDH: false,
		},
		{
			name:   "dst_out_of_range",
			data:   []byte{0x80, 0x01, 0x68, 0x00, 0x01, 0x00},
			wantDH: false,
		},
		{
			name:   "src_out_of_range",
			data:   []byte{0x01, 0x80, 0x68, 0x00, 0x01, 0x00},
			wantDH: false,
		},
		{
			name:   "same_src_dst",
			data:   []byte{0x05, 0x05, 0x68, 0x00, 0x01, 0x00},
			wantDH: false,
		},
		{
			name:   "unknown_command",
			data:   []byte{0x05, 0x01, 0xFF, 0x00, 0x01, 0x00},
			wantDH: false,
		},
		{
			name:   "unknown_status",
			data:   []byte{0x05, 0x01, 0x68, 0x99, 0x01, 0x00},
			wantDH: false,
		},
		{
			name:   "error_response_valid_status",
			data:   []byte{0x01, 0x05, 0x68, 0x10, 0x34, 0x12}, // STS=0x10 (illegal cmd)
			wantDH: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := CheckPayload(tc.data)
			if result.IsDHPlus != tc.wantDH {
				t.Errorf("IsDHPlus: got %v, want %v (reason: %s)", result.IsDHPlus, tc.wantDH, result.Reason)
			}
		})
	}
}

func TestDetectorConfidence(t *testing.T) {
	d := NewDetector()

	// Feed 1 valid frame - should be low confidence
	frame1 := []byte{0x05, 0x01, 0x68, 0x00, 0x01, 0x00, 0x02, 0x07, 0x89, 0x00}
	r := d.Analyze(frame1)
	if !r.IsDHPlus {
		t.Fatal("expected DH+ detection")
	}
	if r.Confidence != ConfidenceLow {
		t.Errorf("1 frame confidence: got %v, want %v", r.Confidence, ConfidenceLow)
	}

	// Feed 2 more frames from same nodes - should reach medium
	frame2 := []byte{0x01, 0x05, 0x68, 0x00, 0x01, 0x00, 0x64, 0x00} // response
	d.Analyze(frame2)
	frame3 := []byte{0x05, 0x01, 0x67, 0x00, 0x02, 0x00, 0x02, 0x07, 0x89, 0x00, 0x64, 0x00}
	r = d.Analyze(frame3)
	if r.Confidence < ConfidenceMedium {
		t.Errorf("3 frames confidence: got %v, want >= %v", r.Confidence, ConfidenceMedium)
	}

	// Feed 7 more frames - should reach high
	for i := 0; i < 7; i++ {
		tns := uint16(i + 10)
		frame := []byte{0x05, 0x01, 0x68, 0x00, byte(tns), byte(tns >> 8), 0x02, 0x07, 0x89, 0x00}
		r = d.Analyze(frame)
	}
	if r.Confidence < ConfidenceHigh {
		t.Errorf("10 frames confidence: got %v, want >= %v", r.Confidence, ConfidenceHigh)
	}
}

func TestDetectorInvalidPayloads(t *testing.T) {
	d := NewDetector()

	// Feed invalid payloads
	r := d.Analyze([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	if r.IsDHPlus {
		t.Error("expected non-DH+ for garbage data")
	}

	total, valid, _, _ := d.Stats()
	if total != 1 || valid != 0 {
		t.Errorf("stats: got total=%d, valid=%d, want total=1, valid=0", total, valid)
	}
}

func TestDetectorMixedPayloads(t *testing.T) {
	d := NewDetector()

	// Valid DH+ frame
	d.Analyze([]byte{0x05, 0x01, 0x68, 0x00, 0x01, 0x00})
	// Invalid
	d.Analyze([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	// Valid
	d.Analyze([]byte{0x05, 0x01, 0x06, 0x00, 0x02, 0x00})

	total, valid, _, _ := d.Stats()
	if total != 3 || valid != 2 {
		t.Errorf("stats: got total=%d, valid=%d, want total=3, valid=2", total, valid)
	}
}

func TestDetectorCommandStats(t *testing.T) {
	d := NewDetector()

	d.Analyze([]byte{0x05, 0x01, 0x68, 0x00, 0x01, 0x00})
	d.Analyze([]byte{0x05, 0x01, 0x68, 0x00, 0x02, 0x00})
	r := d.Analyze([]byte{0x05, 0x01, 0x67, 0x00, 0x03, 0x00})

	if r.CommandStats[CmdTypedRead] != 2 {
		t.Errorf("TypedRead count: got %d, want 2", r.CommandStats[CmdTypedRead])
	}
	if r.CommandStats[CmdTypedWrite] != 1 {
		t.Errorf("TypedWrite count: got %d, want 1", r.CommandStats[CmdTypedWrite])
	}
}
