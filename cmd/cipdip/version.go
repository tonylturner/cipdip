package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintf(os.Stdout, "cipdip version %s\n", version)
			fmt.Fprintf(os.Stdout, "commit: %s\n", commit)
			fmt.Fprintf(os.Stdout, "date: %s\n", date)
		},
	}
}

