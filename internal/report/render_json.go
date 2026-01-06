package report

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// WriteJSONFile marshals a report structure to JSON and writes it to disk.
func WriteJSONFile(path string, report any) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	return nil
}

// WriteJSON writes a report as JSON to an io.Writer.
func WriteJSON(w io.Writer, report any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}
