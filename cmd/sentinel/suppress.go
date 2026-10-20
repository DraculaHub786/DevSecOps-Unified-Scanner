package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/config"
)

func newSuppressCmd() *cobra.Command {
	var (
		reason  string
		expires string
	)

	cmd := &cobra.Command{
		Use:   "suppress <finding-id>",
		Short: "Suppress a security finding in .sentinel.yml with a mandatory justification reason",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			findingID := strings.TrimSpace(args[0])
			if findingID == "" {
				fmt.Fprintln(os.Stderr, "Error: finding ID cannot be empty.")
				os.Exit(2)
			}

			reason = strings.TrimSpace(reason)
			if reason == "" {
				fmt.Fprintln(os.Stderr, "Error: suppression requires a mandatory justification reason via --reason.")
				os.Exit(2)
			}

			if expires != "" {
				if _, err := time.Parse("2006-01-02", expires); err != nil {
					fmt.Fprintf(os.Stderr, "Error: invalid expiration date format %q (must be YYYY-MM-DD).\n", expires)
					os.Exit(2)
				}
			}

			repoPath, _ := filepath.Abs(".")
			cfgFile := filepath.Join(repoPath, ".sentinel.yml")

			var node yaml.Node
			data, err := os.ReadFile(cfgFile)
			if err != nil {
				// If .sentinel.yml does not exist, create from default config
				cfg := config.DefaultConfig()
				cfg.Ignore.Findings = append(cfg.Ignore.Findings, config.FindingSuppression{
					ID:      findingID,
					Reason:  reason,
					Expires: expires,
				})
				out, _ := yaml.Marshal(cfg)
				if err := os.WriteFile(cfgFile, out, 0644); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to write %s: %v\n", cfgFile, err)
					os.Exit(2)
				}
				fmt.Printf("✅ Created %s and suppressed finding %s.\n", cfgFile, findingID)
				return
			}

			if err := yaml.Unmarshal(data, &node); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to parse %s: %v\n", cfgFile, err)
				os.Exit(2)
			}

			// Parse into config struct to update cleanly
			cfg, err := config.Load(repoPath)
			if err != nil {
				cfg = config.DefaultConfig()
			}

			// Check if already suppressed
			found := false
			for i, supp := range cfg.Ignore.Findings {
				if strings.EqualFold(supp.ID, findingID) {
					cfg.Ignore.Findings[i].Reason = reason
					cfg.Ignore.Findings[i].Expires = expires
					found = true
					break
				}
			}
			if !found {
				cfg.Ignore.Findings = append(cfg.Ignore.Findings, config.FindingSuppression{
					ID:      findingID,
					Reason:  reason,
					Expires: expires,
				})
			}

			outData, err := yaml.Marshal(cfg)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Failed to serialize config: %v\n", err)
				os.Exit(2)
			}

			if err := os.WriteFile(cfgFile, outData, 0644); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to update %s: %v\n", cfgFile, err)
				os.Exit(2)
			}

			fmt.Printf("✅ Successfully suppressed finding %q in %s\n", findingID, cfgFile)
			fmt.Printf("   Reason:  %s\n", reason)
			if expires != "" {
				fmt.Printf("   Expires: %s\n", expires)
			}
		},
	}

	cmd.Flags().StringVar(&reason, "reason", "", "Mandatory justification for suppressing finding (e.g. 'False positive verified by AppSec')")
	cmd.Flags().StringVar(&expires, "expires", "", "Optional expiration date for suppression (YYYY-MM-DD)")
	_ = cmd.MarkFlagRequired("reason")

	return cmd
}
