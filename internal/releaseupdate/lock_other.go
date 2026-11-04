//go:build !linux

package releaseupdate

import "sync"

var statusLock sync.Mutex

func lockStatus(string) (func(), error) {
	statusLock.Lock()
	return statusLock.Unlock, nil
}
