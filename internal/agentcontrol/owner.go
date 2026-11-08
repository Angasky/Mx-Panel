package agentcontrol

import (
	"errors"
	"os"
	"syscall"
)

func preserveOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("无法读取文件所有者")
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}
func lockDirectory(dir string) (func(), error) {
	f, e := os.OpenFile(dir+"/operation.lock", os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, e
	}
	return func() { syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}
