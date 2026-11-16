package remote

import "github.com/Angasky/dingzhi-ban/internal/coreapi"

func CoreWriteScript(kind string, previous []byte, next Record) (string, error) {
	return coreapi.WriteScript(kind, previous, next, "", "")
}
func coreWriteScript(kind string, previous []byte, next Record, tag, verify string, keys ...string) (string, error) {
	return coreapi.WriteScript(kind, previous, next, tag, verify, keys...)
}
func protectCoreInbounds(previous, next Record, tag string) error {
	return coreapi.ProtectInbounds(previous, next, tag)
}
