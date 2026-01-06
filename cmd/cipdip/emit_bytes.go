package main

import (
	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/app"
)

type emitBytesFlags struct {
	catalogRoot   string
	catalogKeys   []string
	allCatalog    bool
	outputPath    string
	profileName   string
	responsesOnly bool
}

func newEmitBytesCmd() *cobra.Command {
	flags := &emitBytesFlags{}

	cmd := &cobra.Command{
		Use:   "emit-bytes",
		Short: "Emit ENIP request bytes for catalog operations",
		Long: `Emit ENIP bytes for catalog-defined operations without sending
traffic on the network. Output is JSON for validate-bytes consumption.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if handleHelpArg(cmd, args) {
				return nil
			}
			return runEmitBytes(flags)
		},
	}

	cmd.Flags().StringVar(&flags.catalogRoot, "catalog-root", "", "Workspace root containing catalogs/ for catalog-key resolution")
	cmd.Flags().StringArrayVar(&flags.catalogKeys, "catalog-key", nil, "Catalog key to emit (repeatable)")
	cmd.Flags().BoolVar(&flags.allCatalog, "all", false, "Emit all catalog entries")
	cmd.Flags().StringVar(&flags.outputPath, "output", "", "Write JSON to file (default stdout)")
	cmd.Flags().StringVar(&flags.profileName, "protocol-profile", "strict_odva", "Protocol profile for encoding (strict_odva, legacy_compat, vendor name)")
	cmd.Flags().BoolVar(&flags.responsesOnly, "responses-only", false, "Emit response packets only (subset of supported services)")

	return cmd
}

func runEmitBytes(flags *emitBytesFlags) error {
	return app.RunEmitBytes(app.EmitBytesOptions{
		CatalogRoot:   flags.catalogRoot,
		CatalogKeys:   flags.catalogKeys,
		AllCatalog:    flags.allCatalog,
		OutputPath:    flags.outputPath,
		ProfileName:   flags.profileName,
		ResponsesOnly: flags.responsesOnly,
	})
}
