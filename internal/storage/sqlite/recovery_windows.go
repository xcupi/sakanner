//go:build windows

package sqlite

// processAlive is conservatively always false on Windows (sakanner's
// only supported platform is Ubuntu; this exists purely so the package
// still builds elsewhere). Every "running"/"pending" job found at
// startup is treated as orphaned and reconciled to Failed.
func processAlive(pid int) bool {
	return false
}
