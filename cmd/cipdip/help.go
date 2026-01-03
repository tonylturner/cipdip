package main

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

func handleHelpArg(cmd *cobra.Command, args []string) bool {
	if len(args) == 0 {
		return false
	}
	if strings.EqualFold(args[0], "help") {
		_ = cmd.Help()
		return true
	}
	return false
}

func missingFlagError(cmd *cobra.Command, flag string) error {
	_ = cmd.Help()
	return fmt.Errorf("required flag %s not set", flag)
}
