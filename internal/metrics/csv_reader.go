package metrics

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"
)

// ReadMetricsCSV reads a metrics CSV file and returns the parsed metrics along
// with the first and last timestamps found in the data.
func ReadMetricsCSV(path string) ([]Metric, time.Time, time.Time, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("open metrics CSV: %w", err)
	}
	defer file.Close()

	reader := csv.NewReader(file)

	// Read and validate header
	header, err := reader.Read()
	if err != nil {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("read CSV header: %w", err)
	}

	colIndex := make(map[string]int, len(header))
	for i, col := range header {
		colIndex[col] = i
	}

	requiredCols := []string{"timestamp", "scenario", "operation", "success", "rtt_ms"}
	for _, col := range requiredCols {
		if _, ok := colIndex[col]; !ok {
			return nil, time.Time{}, time.Time{}, fmt.Errorf("CSV missing required column: %s", col)
		}
	}

	var metrics []Metric
	var firstTime, lastTime time.Time
	rowCount := 0

	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, time.Time{}, time.Time{}, fmt.Errorf("read CSV row %d: %w", rowCount+2, err)
		}

		m := Metric{}

		if idx, ok := colIndex["timestamp"]; ok && idx < len(record) {
			if t, err := time.Parse(time.RFC3339Nano, record[idx]); err == nil {
				m.Timestamp = t
				if rowCount == 0 {
					firstTime = t
				}
				lastTime = t
			}
		}
		if idx, ok := colIndex["scenario"]; ok && idx < len(record) {
			m.Scenario = record[idx]
		}
		if idx, ok := colIndex["target_type"]; ok && idx < len(record) {
			m.TargetType = TargetType(record[idx])
		}
		if idx, ok := colIndex["operation"]; ok && idx < len(record) {
			m.Operation = OperationType(record[idx])
		}
		if idx, ok := colIndex["target_name"]; ok && idx < len(record) {
			m.TargetName = record[idx]
		}
		if idx, ok := colIndex["service_code"]; ok && idx < len(record) {
			m.ServiceCode = record[idx]
		}
		if idx, ok := colIndex["success"]; ok && idx < len(record) {
			m.Success = record[idx] == "true"
		}
		if idx, ok := colIndex["rtt_ms"]; ok && idx < len(record) && record[idx] != "" {
			if v, err := strconv.ParseFloat(record[idx], 64); err == nil {
				m.RTTMs = v
			}
		}
		if idx, ok := colIndex["jitter_ms"]; ok && idx < len(record) && record[idx] != "" {
			if v, err := strconv.ParseFloat(record[idx], 64); err == nil {
				m.JitterMs = v
			}
		}
		if idx, ok := colIndex["status"]; ok && idx < len(record) && record[idx] != "" {
			if v, err := strconv.ParseUint(record[idx], 10, 8); err == nil {
				m.Status = uint8(v)
			}
		}
		if idx, ok := colIndex["error"]; ok && idx < len(record) {
			m.Error = record[idx]
		}
		if idx, ok := colIndex["outcome"]; ok && idx < len(record) {
			m.Outcome = record[idx]
		}
		if idx, ok := colIndex["expected_outcome"]; ok && idx < len(record) {
			m.ExpectedOutcome = record[idx]
		}

		metrics = append(metrics, m)
		rowCount++
	}

	if rowCount == 0 {
		return nil, time.Time{}, time.Time{}, fmt.Errorf("no data rows in CSV file")
	}

	return metrics, firstTime, lastTime, nil
}
