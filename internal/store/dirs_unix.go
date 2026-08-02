//go:build unix

package store

import (
	"fmt"
	"os"
	"syscall"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// validateDirOwner rejects directories not owned by the current user (Unix).
// Root (uid 0) may own directories used by privileged installers; non-root
// processes still require their own uid for fail-closed isolation.
func validateDirOwner(path string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		// Platform without Stat_t: skip ownership check.
		return nil
	}
	uid := os.Getuid()
	if uid < 0 {
		// Some environments report -1 when uid is unavailable.
		return nil
	}
	owner := int(st.Uid)
	if owner != uid {
		return apperr.New(apperr.CodeCorruptCache,
			fmt.Sprintf("data directory %q is owned by uid %d, not current uid %d", path, owner, uid))
	}
	return nil
}
