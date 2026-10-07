package collector

import (
	"golang.org/x/sys/unix"
)

// syscallStatFS is the StatFS backed by statfs(2).
type syscallStatFS struct{}

func (syscallStatFS) Stat(path string) (FSStats, error) {
	var s unix.Statfs_t
	if err := unix.Statfs(path, &s); err != nil {
		return FSStats{}, err
	}
	bs := uint64(s.Frsize)
	if bs == 0 {
		bs = uint64(s.Bsize)
	}
	return FSStats{Size: s.Blocks * bs, Free: s.Bfree * bs, Avail: s.Bavail * bs}, nil
}

// systemUname returns uname(2)'s sysname and machine. uname(2) is not
// namespaced for those fields, so inside the container they are the host
// kernel's.
func systemUname() (sysname, machine string, err error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", "", err
	}
	return unix.ByteSliceToString(u.Sysname[:]), unix.ByteSliceToString(u.Machine[:]), nil
}
