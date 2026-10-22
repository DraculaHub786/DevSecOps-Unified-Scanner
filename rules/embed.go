package rules

import "embed"

// Content embeds all rules (*.yml) packaged with the Sentinel scanner binary.
//go:embed *.yml
var Content embed.FS
