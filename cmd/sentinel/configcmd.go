package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
)

func newConfigCmd() *cobra.Command {
	configCmd := &cobra.Command{
		Use:   "config",
		Short: "Inspect, manage, and validate Sentinel scanner configuration",
	}

	configCmd.AddCommand(newConfigValidateCmd())
	return configCmd
}

func newConfigValidateCmd() *cobra.Command {
	var strict bool

	cmd := &cobra.Command{
		Use:   "validate [path]",
		Short: "Validate .sentinel.yml policy syntax, bounds, and security posture",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetPath := ".sentinel.yml"
			if len(args) > 0 {
				targetPath = args[0]
			}

			// If directory, look for .sentinel.yml inside
			fi, err := os.Stat(targetPath)
			if err == nil && fi.IsDir() {
				targetPath = filepath.Join(targetPath, ".sentinel.yml")
			}

			cfg, err := config.LoadFile(targetPath)
			if err != nil {
				return fmt.Errorf("configuration error in %s:\n%w", targetPath, err)
			}

			warnings := config.Audit(cfg)
			if len(warnings) > 0 {
				fmt.Fprintf(cmd.OutOrStdout(), "⚠️ Policy Audit Warnings for %s (%d found):\n", targetPath, len(warnings))
				for _, w := range warnings {
					fmt.Fprintf(cmd.OutOrStdout(), "  • %s\n", w)
				}
				if strict {
					return fmt.Errorf("validation failed under --strict due to %d policy warning(s)", len(warnings))
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "✅ Configuration %s is valid (fail_on: %s, risk_score_max: %.1f)\n", targetPath, cfg.Thresholds.FailOn, cfg.Thresholds.RiskScoreMax)
			return nil
		},
	}

	cmd.Flags().BoolVar(&strict, "strict", false, "Fail validation if any policy warnings or weakened thresholds exist")
	return cmd
}
