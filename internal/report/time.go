package report

import "time"

// FormatTimestamp returns a RFC3339 UTC timestamp string.
func FormatTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}
