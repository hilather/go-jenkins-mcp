//go:build !unix

package update

// freeBytes is unavailable on non-unix (Windows out of scope); skip free-space preflight.
func freeBytes(path string) (int64, bool) {
	return 0, false
}
