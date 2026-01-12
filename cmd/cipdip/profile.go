package main

import (
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/tturner/cipdip/internal/profile"
)

func newProfileCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "profile",
		Short: "Manage and list process profiles",
		Long: `Manage process profiles for realistic CIP traffic generation.

Process profiles define application-shaped behavior including:
- State machines with transitions and events
- Role-based client behavior (HMI, Historian, EWS)
- Tag definitions with update rules
- Write scheduling (timer, state, random triggers)
- MSP batching for realistic traffic patterns

Use 'cipdip profile list' to see available profiles.
Use 'cipdip profile show <name>' to see profile details.`,
	}

	cmd.AddCommand(newProfileListCmd())
	cmd.AddCommand(newProfileShowCmd())

	return cmd
}

func newProfileListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available process profiles",
		Long:  `List all available process profiles from the profiles directory.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := profile.ListProfiles("profiles")
			if err != nil {
				return fmt.Errorf("list profiles: %w", err)
			}

			if len(profiles) == 0 {
				fmt.Println("No profiles found in profiles/ directory")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tPERSONALITY\tSTATES\tTAGS\tROLES\tDESCRIPTION")
			fmt.Fprintln(w, "----\t-----------\t------\t----\t-----\t-----------")
			for _, p := range profiles {
				fmt.Fprintf(w, "%s\t%s\t%d\t%d\t%s\t%s\n",
					p.Name,
					p.Personality,
					p.StateCount,
					p.TagCount,
					formatRoles(p.Roles),
					truncate(p.Description, 40),
				)
			}
			w.Flush()
			return nil
		},
	}
}

func newProfileShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <profile-name>",
		Short: "Show details of a process profile",
		Long:  `Display detailed information about a specific process profile.`,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			p, err := profile.LoadProfileByName(name)
			if err != nil {
				return fmt.Errorf("load profile '%s': %w", name, err)
			}

			fmt.Printf("Profile: %s\n", p.Metadata.Name)
			fmt.Printf("Personality: %s\n", p.Metadata.Personality)
			if p.Metadata.Description != "" {
				fmt.Printf("Description: %s\n", p.Metadata.Description)
			}
			fmt.Println()

			// Tags
			fmt.Printf("Tags (%d):\n", len(p.DataModel.Tags))
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "  NAME\tTYPE\tWRITABLE\tUPDATE RULE")
			for _, tag := range p.DataModel.Tags {
				writable := ""
				if tag.Writable {
					writable = "yes"
				}
				rule := tag.UpdateRule
				if rule == "" {
					rule = "-"
				}
				fmt.Fprintf(w, "  %s\t%s\t%s\t%s\n", tag.Name, tag.Type, writable, rule)
			}
			w.Flush()
			fmt.Println()

			// States
			fmt.Printf("States (%d):\n", len(p.StateMachine.States))
			fmt.Printf("  Initial: %s\n", p.StateMachine.InitialState)
			for name, state := range p.StateMachine.States {
				fmt.Printf("  - %s", name)
				if len(state.Transitions) > 0 {
					fmt.Printf(" (transitions: %d)", len(state.Transitions))
				}
				fmt.Println()
			}
			fmt.Println()

			// Roles
			fmt.Printf("Roles (%d):\n", len(p.Roles))
			for name, role := range p.Roles {
				fmt.Printf("  %s:\n", name)
				if role.Description != "" {
					fmt.Printf("    Description: %s\n", role.Description)
				}
				fmt.Printf("    Poll Interval: %s\n", role.PollInterval)
				fmt.Printf("    Batch Size: %d\n", role.BatchSize)
				fmt.Printf("    Read Tags: %d\n", len(role.ReadTags))
				fmt.Printf("    Write Tags: %d\n", len(role.WriteTags))
				if len(role.WriteEvents) > 0 {
					fmt.Printf("    Write Events: %d\n", len(role.WriteEvents))
				}
			}

			return nil
		},
	}
}

func formatRoles(roles []string) string {
	if len(roles) == 0 {
		return "-"
	}
	result := ""
	for i, r := range roles {
		if i > 0 {
			result += ","
		}
		result += r
	}
	return result
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
