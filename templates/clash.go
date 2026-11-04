package templates

import _ "embed"

// Clash returns the bundled node-free configuration for new subscriptions.
func Clash() string { return clash }

//go:embed clash.yaml
var clash string
