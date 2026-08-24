//go:build !windows

package sqlite

import "syscall"

// processAlive reports whether pid refers to a still-running process.
// Sending signal 0 performs no actual signaling -- the kernel only
// checks whether the process exists and, if so, whether the caller has
// permission to signal it. ESRCH means the process is gone; any other
// outcome (nil, or EPERM for a process owned by another user) means it's
// still alive.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}
