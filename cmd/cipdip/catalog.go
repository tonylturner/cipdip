package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/tonylturner/cipdip/internal/app"
	"github.com/tonylturner/cipdip/internal/cip/catalog"
)

func newCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "CIP service catalog operations",
		Long: `Browse, validate, and test CIP services from the catalog.

The catalog is the definitive source of truth for CIP service definitions,
including service codes, object classes, EPATH specifications, and payloads.`,
	}

	cmd.AddCommand(newCatalogListCmd())
	cmd.AddCommand(newCatalogShowCmd())
	cmd.AddCommand(newCatalogTestCmd())
	cmd.AddCommand(newCatalogValidateCmd())

	return cmd
}

// --- catalog list ---

type catalogListFlags struct {
	domain   string
	category string
	search   string
	groups   bool
}

func newCatalogListCmd() *cobra.Command {
	flags := &catalogListFlags{}

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List catalog entries",
		Long:  `List all CIP service entries in the catalog, optionally filtered by domain or category.`,
		Example: `  cipdip catalog list
  cipdip catalog list --domain core
  cipdip catalog list --domain logix
  cipdip catalog list --category discovery
  cipdip catalog list --search forward
  cipdip catalog list --groups`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogList(flags)
		},
	}

	cmd.Flags().StringVar(&flags.domain, "domain", "", "Filter by domain (core, logix, legacy)")
	cmd.Flags().StringVar(&flags.category, "category", "", "Filter by category (discovery, connection, data_access, etc.)")
	cmd.Flags().StringVar(&flags.search, "search", "", "Search query (matches key, name, description)")
	cmd.Flags().BoolVar(&flags.groups, "groups", false, "Show service groups instead of individual entries")

	return cmd
}

func runCatalogList(flags *catalogListFlags) error {
	cat, err := loadCatalog()
	if err != nil {
		return err
	}

	if flags.groups {
		return listGroups(cat, flags)
	}

	var entries []*catalog.Entry

	// Apply filters
	if flags.search != "" {
		entries = cat.Search(flags.search)
	} else if flags.domain != "" {
		entries = cat.ListByDomain(catalog.Domain(flags.domain))
	} else {
		entries = cat.ListAll()
	}

	// Filter by category if specified
	if flags.category != "" {
		var filtered []*catalog.Entry
		for _, e := range entries {
			if string(e.Category) == flags.category {
				filtered = append(filtered, e)
			}
		}
		entries = filtered
	}

	if len(entries) == 0 {
		fmt.Println("No entries found")
		return nil
	}

	// Print header
	fmt.Printf("%-8s %-28s %-6s %-6s %-6s %s\n",
		"DOMAIN", "KEY", "SVC", "OBJ", "ATTR", "NAME")
	fmt.Println(strings.Repeat("-", 80))

	for _, e := range entries {
		attr := "-"
		if e.EPATH.Attribute != 0 {
			attr = fmt.Sprintf("0x%02X", e.EPATH.Attribute)
		}
		fmt.Printf("%-8s %-28s 0x%02X   0x%02X   %-6s %s\n",
			e.Domain, e.Key, e.ServiceCode, e.ObjectClass, attr, e.Name)
	}

	fmt.Printf("\n%d entries\n", len(entries))
	return nil
}

func listGroups(cat *catalog.Catalog, flags *catalogListFlags) error {
	groups := cat.Groups()

	// Filter by domain if specified
	if flags.domain != "" {
		groups = cat.GroupsByDomain(catalog.Domain(flags.domain))
	}

	if len(groups) == 0 {
		fmt.Println("No groups found")
		return nil
	}

	// Print header
	fmt.Printf("%-8s %-26s %-26s %s\n",
		"DOMAIN", "SERVICE", "OBJECT", "TARGETS")
	fmt.Println(strings.Repeat("-", 100))

	for _, g := range groups {
		service := fmt.Sprintf("%s 0x%02X", g.ServiceName, g.ServiceCode)
		object := fmt.Sprintf("%s 0x%02X", g.ObjectName, g.ObjectClass)
		targets := g.TargetPreview(3)

		fmt.Printf("%-8s %-26s %-26s %s\n",
			g.Domain, service, object, targets)
	}

	fmt.Printf("\n%d groups\n", len(groups))
	return nil
}

// --- catalog show ---

func newCatalogShowCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "show <key>",
		Short: "Show details of a catalog entry",
		Long:  `Display full details of a catalog entry including EPATH, payload schema, and validation status.`,
		Example: `  cipdip catalog show identity.vendor_id
  cipdip catalog show connmgr.forward_open
  cipdip catalog show symbol.read_tag`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogShow(args[0])
		},
	}

	return cmd
}

func runCatalogShow(key string) error {
	cat, err := loadCatalog()
	if err != nil {
		return err
	}

	entry, ok := cat.Lookup(key)
	if !ok {
		return fmt.Errorf("catalog key not found: %s", key)
	}

	fmt.Printf("Key:           %s\n", entry.Key)
	fmt.Printf("Name:          %s\n", entry.Name)
	fmt.Printf("Description:   %s\n", entry.Description)
	fmt.Println()

	fmt.Printf("Service:       %s (0x%02X)\n", entry.ServiceName, entry.ServiceCode)
	fmt.Printf("Object:        %s (0x%02X)\n", entry.ObjectName, entry.ObjectClass)
	fmt.Println()

	fmt.Printf("EPATH Kind:    %s\n", entry.EPATH.Kind)
	if entry.EPATH.Class != 0 {
		fmt.Printf("EPATH Class:   0x%02X\n", entry.EPATH.Class)
	}
	if entry.EPATH.Instance != 0 {
		fmt.Printf("EPATH Instance: 0x%02X\n", entry.EPATH.Instance)
	}
	if entry.EPATH.Attribute != 0 {
		fmt.Printf("EPATH Attribute: 0x%02X\n", entry.EPATH.Attribute)
	}
	fmt.Println()

	fmt.Printf("Domain:        %s\n", entry.Domain)
	fmt.Printf("Category:      %s\n", entry.Category)
	fmt.Printf("Personality:   %s\n", entry.Personality)
	if entry.Vendor != "" {
		fmt.Printf("Vendor:        %s\n", entry.Vendor)
	}
	fmt.Println()

	if len(entry.RequiresInput) > 0 {
		fmt.Printf("Requires Input: %s\n", strings.Join(entry.RequiresInput, ", "))
	}

	if entry.PayloadSchema != nil {
		fmt.Printf("Payload Type:  %s\n", entry.PayloadSchema.Type)
		if len(entry.PayloadSchema.Params) > 0 {
			fmt.Println("Payload Params:")
			for k, v := range entry.PayloadSchema.Params {
				fmt.Printf("  %s: %v\n", k, v)
			}
		}
	}

	return nil
}

// --- catalog test ---

type catalogTestFlags struct {
	ip       string
	port     int
	tag      string
	dryRun   bool
	instance string
}

func newCatalogTestCmd() *cobra.Command {
	flags := &catalogTestFlags{}

	cmd := &cobra.Command{
		Use:   "test <key>",
		Short: "Execute a catalog entry against a target",
		Long: `Send a CIP request based on a catalog entry to a target device.

This command replaces 'cipdip single' with a simpler interface that uses
catalog keys instead of raw service/class/instance/attribute values.`,
		Example: `  cipdip catalog test identity.vendor_id --ip 10.0.0.50
  cipdip catalog test tcpip.hostname --ip 10.0.0.50
  cipdip catalog test symbol.read_tag --ip 10.0.0.50 --tag MyCounter
  cipdip catalog test identity.vendor_id --ip 10.0.0.50 --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if flags.ip == "" {
				return missingFlagError(cmd, "--ip")
			}
			return runCatalogTest(args[0], flags)
		},
	}

	cmd.Flags().StringVar(&flags.ip, "ip", "", "Target CIP adapter IP address (required)")
	cmd.Flags().IntVar(&flags.port, "port", 44818, "CIP TCP port")
	cmd.Flags().StringVar(&flags.tag, "tag", "", "Tag name for symbol operations")
	cmd.Flags().StringVar(&flags.instance, "instance", "", "Override instance ID")
	cmd.Flags().BoolVar(&flags.dryRun, "dry-run", false, "Print request bytes without sending")

	return cmd
}

func runCatalogTest(key string, flags *catalogTestFlags) error {
	cat, err := loadCatalog()
	if err != nil {
		return err
	}

	entry, ok := cat.Lookup(key)
	if !ok {
		return fmt.Errorf("catalog key not found: %s", key)
	}

	// Check required inputs
	for _, input := range entry.RequiresInput {
		if input == "symbol_path" || input == "tag_path" {
			if flags.tag == "" {
				return fmt.Errorf("entry %s requires --tag", key)
			}
		}
	}

	// Build options for app.RunSingle
	opts := app.SingleOptions{
		IP:          flags.ip,
		Port:        flags.port,
		Service:     fmt.Sprintf("0x%02X", entry.ServiceCode),
		ClassID:     fmt.Sprintf("0x%02X", entry.ObjectClass),
		InstanceID:  fmt.Sprintf("0x%02X", entry.EPATH.Instance),
		DryRun:      flags.dryRun,
	}

	if flags.instance != "" {
		opts.InstanceID = flags.instance
	}

	if entry.EPATH.Attribute != 0 {
		opts.AttributeID = fmt.Sprintf("0x%02X", entry.EPATH.Attribute)
	}

	if flags.tag != "" {
		opts.TagPath = flags.tag
	}

	if entry.PayloadSchema != nil {
		opts.PayloadType = entry.PayloadSchema.Type
	}

	fmt.Printf("Testing: %s (%s)\n", entry.Name, entry.Key)
	fmt.Printf("Target:  %s:%d\n", flags.ip, flags.port)
	fmt.Printf("Service: %s (0x%02X) on %s (0x%02X)\n",
		entry.ServiceName, entry.ServiceCode, entry.ObjectName, entry.ObjectClass)
	fmt.Println()

	return app.RunSingle(opts)
}

// --- catalog validate ---

func newCatalogValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate catalog against CIP spec",
		Long: `Check the catalog for consistency and validate entries against
the CIP specification. Reports errors and warnings.`,
		Example: `  cipdip catalog validate`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCatalogValidate()
		},
	}

	return cmd
}

func runCatalogValidate() error {
	cat, err := loadCatalog()
	if err != nil {
		return err
	}

	// Validate structure
	if err := cat.File().Validate(); err != nil {
		return fmt.Errorf("structure validation failed: %w", err)
	}

	// Validate against spec
	result := catalog.ValidateAgainstSpec(cat)

	fmt.Printf("Catalog: %s (v%d)\n", cat.File().Name, cat.File().Version)
	fmt.Printf("Entries: %d\n\n", len(cat.ListAll()))

	if len(result.Errors) > 0 {
		fmt.Println("ERRORS:")
		for _, e := range result.Errors {
			fmt.Printf("  [%s] %s: %s\n", e.Key, e.Field, e.Message)
		}
		fmt.Println()
	}

	if len(result.Warnings) > 0 {
		fmt.Println("WARNINGS:")
		for _, w := range result.Warnings {
			fmt.Printf("  [%s] %s: %s\n", w.Key, w.Field, w.Message)
		}
		fmt.Println()
	}

	if result.IsValid() {
		fmt.Println("Validation: PASS")
		if len(result.Warnings) > 0 {
			fmt.Printf("  %d warnings (acceptable - service codes are context-dependent)\n", len(result.Warnings))
		}
		return nil
	}

	return fmt.Errorf("validation failed with %d errors", len(result.Errors))
}

// --- helpers ---

func loadCatalog() (*catalog.Catalog, error) {
	// Find catalog relative to current working directory
	cwd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("get working directory: %w", err)
	}

	path, err := catalog.FindCoreCatalog(cwd)
	if err != nil {
		// Try relative to executable
		exe, _ := os.Executable()
		if exe != "" {
			path, err = catalog.FindCoreCatalog(filepath.Dir(exe))
		}
		if err != nil {
			return nil, fmt.Errorf("catalog not found: %w", err)
		}
	}

	file, err := catalog.LoadAndValidate(path)
	if err != nil {
		return nil, fmt.Errorf("load catalog: %w", err)
	}

	return catalog.NewCatalog(file), nil
}
