package tui

import (
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// Sparkline renders a mini line chart using braille characters.
// Values should be normalized 0-1 or will be auto-scaled.
func Sparkline(values []float64, width int, s Styles) string {
	if len(values) == 0 || width < 1 {
		return ""
	}

	// Braille patterns for 4 vertical levels (bottom to top)
	// Using dots: ⣀ ⣤ ⣶ ⣿
	blocks := []rune{'⣀', '⣤', '⣶', '⣿'}

	// Auto-scale if needed
	maxVal := 0.0
	for _, v := range values {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	// Sample or pad values to fit width
	sampled := make([]float64, width)
	if len(values) >= width {
		// Downsample
		step := float64(len(values)) / float64(width)
		for i := 0; i < width; i++ {
			idx := int(float64(i) * step)
			if idx >= len(values) {
				idx = len(values) - 1
			}
			sampled[i] = values[idx]
		}
	} else {
		// Pad with zeros on left
		offset := width - len(values)
		for i := 0; i < width; i++ {
			if i < offset {
				sampled[i] = 0
			} else {
				sampled[i] = values[i-offset]
			}
		}
	}

	// Build sparkline
	var result strings.Builder
	for _, v := range sampled {
		normalized := v / maxVal
		level := int(normalized * float64(len(blocks)-1))
		if level < 0 {
			level = 0
		}
		if level >= len(blocks) {
			level = len(blocks) - 1
		}
		result.WriteRune(blocks[level])
	}

	return s.Info.Render(result.String())
}

// BarChart renders a horizontal bar chart.
type BarChart struct {
	Items []BarChartItem
	Width int
}

// BarChartItem is a single bar in the chart.
type BarChartItem struct {
	Label string
	Value float64
	Color lipgloss.Color
}

// Render renders the bar chart.
func (b BarChart) Render(s Styles) string {
	if len(b.Items) == 0 {
		return ""
	}

	// Find max value
	maxVal := 0.0
	maxLabelLen := 0
	for _, item := range b.Items {
		if item.Value > maxVal {
			maxVal = item.Value
		}
		if len(item.Label) > maxLabelLen {
			maxLabelLen = len(item.Label)
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	barWidth := b.Width - maxLabelLen - 10 // Space for label and value
	if barWidth < 10 {
		barWidth = 10
	}

	var lines []string
	for _, item := range b.Items {
		// Label
		label := padRight(item.Label, maxLabelLen)

		// Bar
		filled := int((item.Value / maxVal) * float64(barWidth))
		bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

		// Color the bar
		barStyle := lipgloss.NewStyle().Foreground(item.Color)
		bar = barStyle.Render(bar)

		// Value
		value := fmt.Sprintf("%6.0f", item.Value)

		lines = append(lines, fmt.Sprintf("%s %s %s", s.Dim.Render(label), bar, s.Dim.Render(value)))
	}

	return strings.Join(lines, "\n")
}

// Gauge renders a circular-style gauge using Unicode.
func Gauge(label string, value, maxValue float64, width int, s Styles) string {
	if maxValue == 0 {
		maxValue = 100
	}
	percent := (value / maxValue) * 100
	if percent > 100 {
		percent = 100
	}
	if percent < 0 {
		percent = 0
	}

	barWidth := width - len(label) - 8 // Space for label and percentage
	if barWidth < 5 {
		barWidth = 5
	}

	filled := int((percent / 100) * float64(barWidth))

	// Choose color based on percentage
	var color lipgloss.Color
	switch {
	case percent >= 80:
		color = DefaultTheme.Error
	case percent >= 60:
		color = DefaultTheme.Warning
	default:
		color = DefaultTheme.Success
	}

	barStyle := lipgloss.NewStyle().Foreground(color)
	emptyStyle := lipgloss.NewStyle().Foreground(DefaultTheme.TextMuted)

	bar := barStyle.Render(strings.Repeat("━", filled)) +
		emptyStyle.Render(strings.Repeat("━", barWidth-filled))

	percentStr := fmt.Sprintf("%5.1f%%", percent)

	return fmt.Sprintf("%s %s %s", s.Dim.Render(label), bar, s.Dim.Render(percentStr))
}

// MiniTable renders a compact key-value table.
func MiniTable(items [][]string, s Styles) string {
	if len(items) == 0 {
		return ""
	}

	// Find max key length
	maxKeyLen := 0
	for _, item := range items {
		if len(item) > 0 && len(item[0]) > maxKeyLen {
			maxKeyLen = len(item[0])
		}
	}

	var lines []string
	for _, item := range items {
		if len(item) < 2 {
			continue
		}
		key := padRight(item[0], maxKeyLen)
		value := item[1]
		lines = append(lines, s.Dim.Render(key)+" "+value)
	}

	return strings.Join(lines, "\n")
}

// ActivityDots renders activity indicator dots.
func ActivityDots(active int, total int, s Styles) string {
	var dots strings.Builder
	for i := 0; i < total; i++ {
		if i < active {
			dots.WriteString(s.Success.Render("●"))
		} else {
			dots.WriteString(s.Muted.Render("○"))
		}
	}
	return dots.String()
}

// VerticalBar renders vertical bars (like a mini histogram).
func VerticalBar(values []float64, height int, width int, s Styles) string {
	if len(values) == 0 || height < 1 || width < 1 {
		return ""
	}

	// Blocks for vertical bars (bottom to top): ▁▂▃▄▅▆▇█
	blocks := []rune{' ', '▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

	// Find max
	maxVal := 0.0
	for _, v := range values {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	// Sample values to width
	sampled := make([]float64, width)
	if len(values) >= width {
		step := float64(len(values)) / float64(width)
		for i := 0; i < width; i++ {
			idx := int(float64(i) * step)
			if idx >= len(values) {
				idx = len(values) - 1
			}
			sampled[i] = values[idx]
		}
	} else {
		offset := width - len(values)
		for i := 0; i < width; i++ {
			if i < offset {
				sampled[i] = 0
			} else {
				sampled[i] = values[i-offset]
			}
		}
	}

	// Build rows from top to bottom
	rows := make([]string, height)
	for row := 0; row < height; row++ {
		var rowStr strings.Builder
		threshold := float64(height-row) / float64(height)

		for _, v := range sampled {
			normalized := v / maxVal
			if normalized >= threshold {
				// Full or partial block
				blockIdx := int((normalized - threshold) * float64(height) * float64(len(blocks)-1))
				if blockIdx >= len(blocks) {
					blockIdx = len(blocks) - 1
				}
				if blockIdx < 1 && normalized >= threshold {
					blockIdx = len(blocks) - 1 // Full block when at or above threshold
				}
				rowStr.WriteRune(blocks[blockIdx])
			} else {
				rowStr.WriteRune(' ')
			}
		}
		rows[row] = rowStr.String()
	}

	return s.Info.Render(strings.Join(rows, "\n"))
}

// BigNumber renders a large styled number with label.
func BigNumber(value string, label string, color lipgloss.Color, s Styles) string {
	numStyle := lipgloss.NewStyle().
		Foreground(color).
		Bold(true)

	return numStyle.Render(value) + "\n" + s.Dim.Render(label)
}

// StatusGrid renders a grid of status items.
func StatusGrid(items []StatusGridItem, columns int, s Styles) string {
	if len(items) == 0 {
		return ""
	}
	if columns < 1 {
		columns = 2
	}

	var rows []string
	for i := 0; i < len(items); i += columns {
		var cols []string
		for j := 0; j < columns && i+j < len(items); j++ {
			item := items[i+j]
			icon := StatusIcon(item.Status, s)
			cols = append(cols, fmt.Sprintf("%s %s", icon, padRight(item.Label, 15)))
		}
		rows = append(rows, strings.Join(cols, "  "))
	}

	return strings.Join(rows, "\n")
}

// StatusGridItem is an item in a status grid.
type StatusGridItem struct {
	Label  string
	Status string // "success", "error", "warning", "running", "pending"
}

// HeatmapRow renders a single row of a heatmap.
func HeatmapRow(label string, values []float64, width int, s Styles) string {
	if width < 1 {
		width = 20
	}

	// Heat colors from cool to hot
	heatColors := []lipgloss.Color{
		lipgloss.Color("#1a1b26"), // Very low - dark
		lipgloss.Color("#414868"), // Low
		lipgloss.Color("#7aa2f7"), // Medium-low - blue
		lipgloss.Color("#9ece6a"), // Medium - green
		lipgloss.Color("#e0af68"), // Medium-high - amber
		lipgloss.Color("#f7768e"), // High - red
	}

	// Find max
	maxVal := 0.0
	for _, v := range values {
		if v > maxVal {
			maxVal = v
		}
	}
	if maxVal == 0 {
		maxVal = 1
	}

	// Sample to width
	sampled := make([]float64, width)
	if len(values) >= width {
		step := float64(len(values)) / float64(width)
		for i := 0; i < width; i++ {
			idx := int(float64(i) * step)
			if idx >= len(values) {
				idx = len(values) - 1
			}
			sampled[i] = values[idx]
		}
	} else {
		for i := 0; i < width && i < len(values); i++ {
			sampled[i] = values[i]
		}
	}

	var cells strings.Builder
	for _, v := range sampled {
		normalized := v / maxVal
		colorIdx := int(normalized * float64(len(heatColors)-1))
		if colorIdx >= len(heatColors) {
			colorIdx = len(heatColors) - 1
		}
		style := lipgloss.NewStyle().Background(heatColors[colorIdx])
		cells.WriteString(style.Render(" "))
	}

	return s.Dim.Render(padRight(label, 8)) + " " + cells.String()
}

// TrafficGraph renders a scrolling traffic graph.
type TrafficGraph struct {
	Title   string
	Values  []float64
	Width   int
	Height  int
	MaxVal  float64
	ShowMax bool
	Color   lipgloss.Color // Optional color for the graph
}

// TrafficSeries represents a single data series with a color.
type TrafficSeries struct {
	Values []float64
	Color  lipgloss.Color
	Label  string
}

// ColoredTrafficGraph renders multiple series with different colors.
type ColoredTrafficGraph struct {
	Title   string
	Series  []TrafficSeries // Stacked series: reads, writes, errors, other
	Width   int
	Height  int
	ShowMax bool
}

// Render renders the colored traffic graph with stacked series using braille dots.
func (t ColoredTrafficGraph) Render(s Styles) string {
	if t.Width < 10 {
		t.Width = 40
	}
	if t.Height < 3 {
		t.Height = 6
	}

	graphWidth := t.Width - 2

	// Calculate totals and max for each column
	totals := make([]float64, graphWidth)
	var maxVal float64

	for _, series := range t.Series {
		sampled := sampleValues(series.Values, graphWidth)
		for i := 0; i < graphWidth; i++ {
			totals[i] += sampled[i]
			if totals[i] > maxVal {
				maxVal = totals[i]
			}
		}
	}
	if maxVal == 0 {
		maxVal = 100
	}

	// Pre-sample each series
	sampledSeries := make([][]float64, len(t.Series))
	for si, series := range t.Series {
		sampledSeries[si] = sampleValues(series.Values, graphWidth)
	}

	// Build graph rows
	var rows []string

	// Title row
	titleLine := t.Title
	if t.ShowMax {
		titleLine += fmt.Sprintf(" (max: %.0f)", maxVal)
	}
	rows = append(rows, s.Header.Render(titleLine))

	// Braille dot patterns (4 vertical levels)
	braille := []string{"⠀", "⣀", "⣤", "⣶", "⣿"}

	// Graph rows (top to bottom)
	for row := t.Height - 1; row >= 0; row-- {
		var rowStr strings.Builder
		rowStr.WriteString("│")

		rowTop := float64(row+1) / float64(t.Height)
		rowBot := float64(row) / float64(t.Height)

		for col := 0; col < graphWidth; col++ {
			// Calculate cumulative height at this column
			cumulative := 0.0
			char := " "
			var charColor lipgloss.Color

			for si, series := range t.Series {
				prevCum := cumulative
				cumulative += sampledSeries[si][col]
				normalized := cumulative / maxVal
				prevNorm := prevCum / maxVal

				if normalized > rowBot && prevNorm < rowTop {
					// This series contributes to this row
					charColor = series.Color

					if normalized >= rowTop {
						// Full braille block
						char = braille[len(braille)-1]
					} else {
						// Partial braille block
						fillRatio := (normalized - rowBot) / (rowTop - rowBot)
						level := int(fillRatio * float64(len(braille)-1))
						if level >= len(braille) {
							level = len(braille) - 1
						}
						if level < 0 {
							level = 0
						}
						char = braille[level]
					}
				}
			}

			if char != " " && charColor != "" {
				rowStr.WriteString(lipgloss.NewStyle().Foreground(charColor).Render(char))
			} else {
				rowStr.WriteString(char)
			}
		}
		rowStr.WriteString("│")
		rows = append(rows, rowStr.String())
	}

	// Bottom border
	rows = append(rows, "└"+strings.Repeat("─", graphWidth)+"┘")

	return strings.Join(rows, "\n")
}

// sampleValues resamples a slice to the target width.
func sampleValues(values []float64, width int) []float64 {
	sampled := make([]float64, width)
	if len(values) == 0 {
		return sampled
	}
	if len(values) >= width {
		offset := len(values) - width
		for i := 0; i < width; i++ {
			sampled[i] = values[offset+i]
		}
	} else {
		offset := width - len(values)
		for i := 0; i < width; i++ {
			if i < offset {
				sampled[i] = 0
			} else {
				sampled[i] = values[i-offset]
			}
		}
	}
	return sampled
}

// Render renders the traffic graph.
func (t TrafficGraph) Render(s Styles) string {
	if t.Width < 10 {
		t.Width = 40
	}
	if t.Height < 3 {
		t.Height = 6
	}

	// Find max value
	maxVal := t.MaxVal
	if maxVal == 0 {
		for _, v := range t.Values {
			if v > maxVal {
				maxVal = v
			}
		}
	}
	if maxVal == 0 {
		maxVal = 100
	}

	// Graph characters (braille dots)
	blocks := []string{"⠀", "⣀", "⣤", "⣶", "⣿"}

	// Sample values
	graphWidth := t.Width - 2 // Border
	sampled := sampleValues(t.Values, graphWidth)

	// Determine style for graph elements
	graphStyle := s.Info
	if t.Color != "" {
		graphStyle = lipgloss.NewStyle().Foreground(t.Color)
	}

	// Build graph rows
	var rows []string

	// Title row
	titleLine := t.Title
	if t.ShowMax {
		titleLine += fmt.Sprintf(" (max: %.0f)", maxVal)
	}
	rows = append(rows, s.Header.Render(titleLine))

	// Graph rows (top to bottom)
	for row := t.Height - 1; row >= 0; row-- {
		var rowStr strings.Builder
		rowStr.WriteString("│")

		rowTop := float64(row+1) / float64(t.Height)
		rowBot := float64(row) / float64(t.Height)

		for _, v := range sampled {
			normalized := v / maxVal
			if normalized > 1 {
				normalized = 1
			}

			if normalized >= rowTop {
				// Full block
				rowStr.WriteString(graphStyle.Render(blocks[4]))
			} else if normalized > rowBot {
				// Partial block
				level := int((normalized - rowBot) / (rowTop - rowBot) * float64(len(blocks)-1))
				if level >= len(blocks) {
					level = len(blocks) - 1
				}
				rowStr.WriteString(graphStyle.Render(blocks[level]))
			} else {
				rowStr.WriteString(" ")
			}
		}
		rowStr.WriteString("│")
		rows = append(rows, rowStr.String())
	}

	// Bottom border
	rows = append(rows, "└"+strings.Repeat("─", graphWidth)+"┘")

	return strings.Join(rows, "\n")
}

// formatNumber formats a number with K/M/B suffix.
func formatNumber(n float64) string {
	switch {
	case n >= 1_000_000_000:
		return fmt.Sprintf("%.1fB", n/1_000_000_000)
	case n >= 1_000_000:
		return fmt.Sprintf("%.1fM", n/1_000_000)
	case n >= 1_000:
		return fmt.Sprintf("%.1fK", n/1_000)
	default:
		return fmt.Sprintf("%.0f", n)
	}
}

// formatDuration formats a duration in a compact form.
func formatDuration(seconds float64) string {
	if seconds < 60 {
		return fmt.Sprintf("%.0fs", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%.0fm", seconds/60)
	}
	return fmt.Sprintf("%.1fh", seconds/3600)
}

// Clamp clamps a value between min and max.
func Clamp(v, min, max float64) float64 {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// Lerp linearly interpolates between a and b.
func Lerp(a, b, t float64) float64 {
	return a + (b-a)*t
}

// SmoothValues applies simple smoothing to values.
func SmoothValues(values []float64, window int) []float64 {
	if window < 1 || len(values) < window {
		return values
	}

	result := make([]float64, len(values))
	for i := range values {
		sum := 0.0
		count := 0
		for j := i - window/2; j <= i+window/2; j++ {
			if j >= 0 && j < len(values) {
				sum += values[j]
				count++
			}
		}
		result[i] = sum / float64(count)
	}
	return result
}

// Normalize normalizes values to 0-1 range.
func Normalize(values []float64) []float64 {
	if len(values) == 0 {
		return values
	}

	min, max := values[0], values[0]
	for _, v := range values {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}

	if max == min {
		result := make([]float64, len(values))
		for i := range result {
			result[i] = 0.5
		}
		return result
	}

	result := make([]float64, len(values))
	for i, v := range values {
		result[i] = (v - min) / (max - min)
	}
	return result
}

// GenerateTestData generates sample data for testing charts.
func GenerateTestData(count int) []float64 {
	data := make([]float64, count)
	for i := range data {
		// Sin wave with noise
		data[i] = 50 + 30*math.Sin(float64(i)*0.2) + float64(i%10)
	}
	return data
}
