package main

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/DraculaHub786/DevSecOps-Unified-Scanner/internal/doctor"
)

func newDoctorCmd() *cobra.Command {
	var jsonOutput bool

	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Inspect scanner engine availability, versions, and full vs lite mode",
		Run: func(cmd *cobra.Command, args []string) {
			statuses := doctor.CheckEngines()

			if jsonOutput {
				data, _ := json.MarshalIndent(statuses, "", "  ")
				fmt.Println(string(data))
				return
			}

			fmt.Println("\n🩺 Sentinel Engine Diagnostics & Availability")
			fmt.Println("==========================================================================================")
			fmt.Printf("%-26s %-16s %-10s %s\n", "ENGINE", "MODE", "STATUS", "VERSION / DETAILS")
			fmt.Println("------------------------------------------------------------------------------------------")

			allExternal := true
			for _, st := range statuses {
				statusStr := "❌ Missing"
				if st.Found {
					statusStr = "✅ Installed"
				} else {
					allExternal = false
				}

				modeLabel := "External CLI"
				if st.Mode == "embedded lite" {
					modeLabel = "Embedded Lite"
				}

				fmt.Printf("%-26s %-16s %-10s %s\n", st.Name, modeLabel, statusStr, st.Version)
				if !st.Found && st.Recommended != "" {
					fmt.Printf("   💡 %s\n", st.Recommended)
				}
			}

			fmt.Println("------------------------------------------------------------------------------------------")
			if allExternal {
				fmt.Println("🚀 All 5 security scanning engines are installed! Full production scanning active.")
			} else {
				fmt.Println("⚠️  One or more external engines missing. Sentinel will operate in 'lite' mode for those.")
				fmt.Println("   Note: In CI mode (--ci), missing engines will halt the build unless --allow-lite is given.")
			}
			fmt.Println("==========================================================================================")
			fmt.Println()
		},
	}

	cmd.Flags().BoolVar(&jsonOutput, "json", false, "Output diagnostics in JSON format")
	return cmd
}
