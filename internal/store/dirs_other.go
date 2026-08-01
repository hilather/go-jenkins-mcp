//go:build !unix

package store

import "os"

// validateDirOwner is a no-op on non-Unix platforms (Windows is out of scope;
// Tier-1 is Rocky Linux + Ubuntu per architecture §19).
func validateDirOwner(path string, fi os.FileInfo) error {
	_ = path
	_ = fi
	return nil
}
