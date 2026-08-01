//go:build unix

package update

import "syscall"

// freeBytes returns available bytes on the filesystem containing path.
func freeBytes(path string) (int64, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, false
	}
	// Bavail * Bsize — available to non-root.
	return int64(st.Bavail) * int64(st.Bsize), true
}
