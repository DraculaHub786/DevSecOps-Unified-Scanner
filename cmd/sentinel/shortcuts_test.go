package main

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestShortcutsSharedFlagsParity(t *testing.T) {
	shortcuts := []struct {
		name string
		cmd  func() *cobra.Command
	}{
		{name: "sast", cmd: newSASTCmd},
		{name: "secrets", cmd: newSecretsCmd},
		{name: "deps", cmd: newDepsCmd},
		{name: "iac", cmd: newIaCCmd},
	}

	requiredFlags := []string{
		"format",
		"out",
		"fail-on",
		"offline",
		"changed-only",
		"baseline",
		"config",
		"ci",
		"allow-lite",
		"no-color",
	}

	for _, sc := range shortcuts {
		c := sc.cmd()
		for _, flagName := range requiredFlags {
			t.Run(sc.name+"/"+flagName, func(t *testing.T) {
				f := c.Flags().Lookup(flagName)
				if f == nil {
					t.Fatalf("Shortcut command %q is missing required shared flag --%s", sc.name, flagName)
				}
			})
		}
	}
}
