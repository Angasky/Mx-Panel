package deploy

import _ "embed"

// Installer is the trusted installer from the running release.
//
//go:embed install-go.sh
var Installer string

// Menu is shipped inside the Go binary; opening mx-p needs no network.
//
//go:embed mx-p.sh
var Menu string
