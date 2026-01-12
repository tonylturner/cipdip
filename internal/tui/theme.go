package tui

import "github.com/charmbracelet/lipgloss"

// Theme defines the color palette for the TUI.
// Inspired by btop and Tokyo Night color scheme.
type Theme struct {
	// Backgrounds
	BgDark   lipgloss.Color // Deep background
	BgPanel  lipgloss.Color // Panel/box background
	BgAccent lipgloss.Color // Accent background (selection)

	// Text
	TextPrimary lipgloss.Color // Main text
	TextDim     lipgloss.Color // Secondary/dim text
	TextMuted   lipgloss.Color // Very dim text

	// Borders
	Border        lipgloss.Color // Default border
	BorderFocused lipgloss.Color // Focused/active border

	// Semantic colors
	Accent  lipgloss.Color // Primary accent (blue)
	Success lipgloss.Color // Success/positive (green)
	Warning lipgloss.Color // Warning/caution (amber)
	Error   lipgloss.Color // Error/danger (red/pink)
	Info    lipgloss.Color // Info/neutral (cyan)
	Purple  lipgloss.Color // Alternative accent
	Cyan    lipgloss.Color // Cyan for special highlights

	// Status
	Running lipgloss.Color // Active operation
	Pending lipgloss.Color // Waiting state
}

// DefaultTheme returns the default dark theme inspired by btop/Tokyo Night.
var DefaultTheme = Theme{
	// Backgrounds - deep blue-black tones
	BgDark:   lipgloss.Color("#1a1b26"),
	BgPanel:  lipgloss.Color("#24283b"),
	BgAccent: lipgloss.Color("#414868"),

	// Text - soft white to gray gradient
	TextPrimary: lipgloss.Color("#c0caf5"),
	TextDim:     lipgloss.Color("#565f89"),
	TextMuted:   lipgloss.Color("#414868"),

	// Borders
	Border:        lipgloss.Color("#414868"),
	BorderFocused: lipgloss.Color("#7aa2f7"),

	// Semantic colors
	Accent:  lipgloss.Color("#7aa2f7"), // Blue
	Success: lipgloss.Color("#9ece6a"), // Green
	Warning: lipgloss.Color("#e0af68"), // Amber
	Error:   lipgloss.Color("#f7768e"), // Red/Pink
	Info:    lipgloss.Color("#7dcfff"), // Cyan
	Purple:  lipgloss.Color("#bb9af7"), // Purple
	Cyan:    lipgloss.Color("#7dcfff"), // Cyan (same as Info)

	// Status
	Running: lipgloss.Color("#e0af68"), // Amber for running
	Pending: lipgloss.Color("#565f89"), // Dim for pending
}

// Styles provides pre-configured lipgloss styles using the theme.
type Styles struct {
	// Base styles
	Base       lipgloss.Style
	Focused    lipgloss.Style
	Dim        lipgloss.Style
	Muted      lipgloss.Style
	Bold       lipgloss.Style
	Underlined lipgloss.Style

	// Headers
	Title       lipgloss.Style
	Header      lipgloss.Style
	SectionName lipgloss.Style

	// Status indicators
	Success lipgloss.Style
	Warning lipgloss.Style
	Error   lipgloss.Style
	Info    lipgloss.Style
	Running lipgloss.Style

	// Interactive elements
	Selected   lipgloss.Style
	Cursor     lipgloss.Style
	KeyBinding lipgloss.Style
	KeyHint    lipgloss.Style

	// Containers
	Panel      lipgloss.Style
	PanelTitle lipgloss.Style
	Box        lipgloss.Style
	BoxFocused lipgloss.Style

	// Form elements
	Label       lipgloss.Style
	Input       lipgloss.Style
	InputActive lipgloss.Style
	Placeholder lipgloss.Style

	// Progress
	ProgressFilled lipgloss.Style
	ProgressEmpty  lipgloss.Style

	// Footer
	Footer lipgloss.Style
}

// NewStyles creates a new Styles instance from a Theme.
func NewStyles(t Theme) Styles {
	return Styles{
		// Base styles
		Base:       lipgloss.NewStyle().Foreground(t.TextPrimary),
		Focused:    lipgloss.NewStyle().Foreground(t.Accent),
		Dim:        lipgloss.NewStyle().Foreground(t.TextDim),
		Muted:      lipgloss.NewStyle().Foreground(t.TextMuted),
		Bold:       lipgloss.NewStyle().Foreground(t.TextPrimary).Bold(true),
		Underlined: lipgloss.NewStyle().Foreground(t.TextPrimary).Underline(true),

		// Headers
		Title: lipgloss.NewStyle().
			Foreground(t.Accent).
			Bold(true).
			Padding(0, 1),
		Header: lipgloss.NewStyle().
			Foreground(t.Accent).
			Bold(true),
		SectionName: lipgloss.NewStyle().
			Foreground(t.TextDim).
			Bold(true),

		// Status indicators
		Success: lipgloss.NewStyle().Foreground(t.Success),
		Warning: lipgloss.NewStyle().Foreground(t.Warning),
		Error:   lipgloss.NewStyle().Foreground(t.Error),
		Info:    lipgloss.NewStyle().Foreground(t.Info),
		Running: lipgloss.NewStyle().Foreground(t.Running).Bold(true),

		// Interactive elements
		Selected: lipgloss.NewStyle().
			Foreground(t.Accent).
			Bold(true),
		Cursor: lipgloss.NewStyle().
			Foreground(t.BgDark).
			Background(t.Accent),
		KeyBinding: lipgloss.NewStyle().
			Foreground(t.Accent).
			Bold(true),
		KeyHint: lipgloss.NewStyle().
			Foreground(t.TextDim),

		// Containers
		Panel: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(t.Border).
			Padding(1, 2),
		PanelTitle: lipgloss.NewStyle().
			Foreground(t.Accent).
			Bold(true).
			Padding(0, 1),
		Box: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(t.Border).
			Padding(0, 1),
		BoxFocused: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(t.BorderFocused).
			Padding(0, 1),

		// Form elements
		Label: lipgloss.NewStyle().
			Foreground(t.TextDim).
			Width(12),
		Input: lipgloss.NewStyle().
			Foreground(t.TextPrimary),
		InputActive: lipgloss.NewStyle().
			Foreground(t.Accent),
		Placeholder: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		// Progress
		ProgressFilled: lipgloss.NewStyle().
			Foreground(t.Accent),
		ProgressEmpty: lipgloss.NewStyle().
			Foreground(t.TextMuted),

		// Footer
		Footer: lipgloss.NewStyle().
			Foreground(t.TextDim),
	}
}

// DefaultStyles returns styles using the default theme.
var DefaultStyles = NewStyles(DefaultTheme)

// StatusIcon returns a colored status indicator.
func StatusIcon(status string, s Styles) string {
	switch status {
	case "success", "ok", "done", "completed":
		return s.Success.Render("●")
	case "error", "failed", "fail":
		return s.Error.Render("●")
	case "warning", "warn":
		return s.Warning.Render("●")
	case "running", "active":
		return s.Running.Render("●")
	case "pending", "waiting":
		return s.Dim.Render("○")
	default:
		return s.Dim.Render("○")
	}
}

// CheckIcon returns a styled check/cross icon.
func CheckIcon(checked bool, s Styles) string {
	if checked {
		return s.Success.Render("✓")
	}
	return s.Error.Render("✗")
}

// RadioIcon returns a styled radio button.
func RadioIcon(selected bool, s Styles) string {
	if selected {
		return s.Selected.Render("●")
	}
	return s.Dim.Render("○")
}

// CheckboxIcon returns a styled checkbox.
func CheckboxIcon(checked bool, s Styles) string {
	if checked {
		return s.Success.Render("[✓]")
	}
	return s.Dim.Render("[ ]")
}
