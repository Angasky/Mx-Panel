package deploy

import _ "embed"

// Installer is the trusted installer from the running release.
//
//go:embed install-go.sh
var Installer string
