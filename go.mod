module github.com/Angasky/dingzhi-ban

go 1.26.0

require go.yaml.in/yaml/v3 v3.0.6

require (
	github.com/skip2/go-qrcode v0.0.0-20200617195104-da1b6568686e
	golang.org/x/crypto v0.58.0
)

require golang.org/x/sys v0.49.0 // indirect

// v3.0.6 with a bounded emitter event queue; see third_party/yaml/PATCHES.md.
replace go.yaml.in/yaml/v3 => ./third_party/yaml
