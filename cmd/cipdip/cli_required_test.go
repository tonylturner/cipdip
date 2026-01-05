package main

import (
	"io"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestRequiredFlagsErrors(t *testing.T) {
	tests := []struct {
		name    string
		cmd     func() *cobra.Command
		args    []string
		wantErr string
	}{
		{
			name:    "pcap-summary missing input",
			cmd:     newPcapSummaryCmd,
			args:    nil,
			wantErr: "required flag --input not set",
		},
		{
			name:    "pcap-replay missing input",
			cmd:     newPcapReplayCmd,
			args:    nil,
			wantErr: "required flag --input not set",
		},
		{
			name:    "pcap-validate missing input",
			cmd:     newPcapValidateCmd,
			args:    nil,
			wantErr: "required flag --input or --pcap-dir not set",
		},
		{
			name:    "single missing ip",
			cmd:     newSingleCmd,
			args:    nil,
			wantErr: "required flag --ip not set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := tt.cmd()
			cmd.SetOut(io.Discard)
			cmd.SetErr(io.Discard)
			cmd.SetArgs(tt.args)
			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error: got %q want %q", err.Error(), tt.wantErr)
			}
		})
	}
}
