package config

import (
	"os"
	"path/filepath"
)

const appDirName = "jenkins-mcp"

// Paths holds XDG-aligned filesystem locations for non-secret data.
// Secrets never live under these trees; see package keyring.
type Paths struct {
	// ConfigDir is $XDG_CONFIG_HOME/jenkins-mcp (profiles, non-secret config).
	ConfigDir string
	// DataDir is $XDG_DATA_HOME/jenkins-mcp (per-profile data roots).
	DataDir string
	// CacheDir is $XDG_CACHE_HOME/jenkins-mcp.
	CacheDir string
}

// ProfilesDir returns the directory that holds per-profile JSON files.
func (p Paths) ProfilesDir() string {
	return filepath.Join(p.ConfigDir, "profiles")
}

// ProfileFile returns the path for a single profile document.
func (p Paths) ProfileFile(id string) string {
	return filepath.Join(p.ProfilesDir(), id+".json")
}

// PolicyDir returns the directory for enterprise policy overlays (CFG-002).
// Default: $XDG_CONFIG_HOME/jenkins-mcp/policy/
func (p Paths) PolicyDir() string {
	return filepath.Join(p.ConfigDir, "policy")
}

// DefaultPolicyFile returns the default enterprise overlay path (overlay.json).
// Override with JENKINS_MCP_POLICY_FILE (resolved in package policy).
// Signed bundles may use overlay.bundle.json via the same override or by
// placing a bundle at this path; content detection is in package policy.
func (p Paths) DefaultPolicyFile() string {
	return filepath.Join(p.PolicyDir(), "overlay.json")
}

// DefaultPolicyBundleFile returns the conventional signed-bundle path.
// Operators may point JENKINS_MCP_POLICY_FILE at this path explicitly.
func (p Paths) DefaultPolicyBundleFile() string {
	return filepath.Join(p.PolicyDir(), "overlay.bundle.json")
}

// TrustedKeysDir returns the directory for enterprise policy public keys (MGR-001).
// Default: $XDG_CONFIG_HOME/jenkins-mcp/policy/trusted_keys/
// Override with JENKINS_MCP_POLICY_TRUSTED_KEYS (file or directory).
func (p Paths) TrustedKeysDir() string {
	return filepath.Join(p.PolicyDir(), "trusted_keys")
}

// UpdateDir returns the directory for update-lifecycle config (UPD-001).
// Default: $XDG_CONFIG_HOME/jenkins-mcp/update/
func (p Paths) UpdateDir() string {
	return filepath.Join(p.ConfigDir, "update")
}

// UpdateTrustedKeysDir returns the directory for update-manifest public keys (UPD-001).
// Default: $XDG_CONFIG_HOME/jenkins-mcp/update/trusted_keys/
// Override with JENKINS_MCP_UPDATE_TRUSTED_KEYS (file or directory).
func (p Paths) UpdateTrustedKeysDir() string {
	return filepath.Join(p.UpdateDir(), "trusted_keys")
}

// UpdateDataDir returns the data directory for update-lifecycle records (UPD-001).
// Default: $XDG_DATA_HOME/jenkins-mcp/update/
// Holds last-known-good (LKG) after successful verified download — secret-free only.
func (p Paths) UpdateDataDir() string {
	return filepath.Join(p.DataDir, "update")
}

// UpdateLKGFile returns the last-known-good update record path (UPD-001).
// Default: $XDG_DATA_HOME/jenkins-mcp/update/last_known_good.json
// Contents are secret-free (version, channel, artifact sha256, basename, key ids).
func (p Paths) UpdateLKGFile() string {
	return filepath.Join(p.UpdateDataDir(), "last_known_good.json")
}

// PolicyLastGoodFile returns the last-verified bundle cache path (MGR-001).
// Default: $XDG_CACHE_HOME/jenkins-mcp/policy/last_good.json
// Contents are secret-free (bundle_seq, content hash, key_id only).
func (p Paths) PolicyLastGoodFile() string {
	return filepath.Join(p.CacheDir, "policy", "last_good.json")
}

// ProfileDataDir returns the default data root for a profile id under DataDir.
func (p Paths) ProfileDataDir(id string) string {
	return filepath.Join(p.DataDir, "profiles", id)
}

// Resolve returns Paths derived from the environment (XDG_* and HOME).
// Override env vars are honored when set and non-empty.
func Resolve() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		// Fail closed: without a home we cannot place per-user config safely.
		if err == nil {
			err = errNoHome
		}
		return Paths{}, err
	}

	configHome := os.Getenv("XDG_CONFIG_HOME")
	if configHome == "" {
		configHome = filepath.Join(home, ".config")
	}
	dataHome := os.Getenv("XDG_DATA_HOME")
	if dataHome == "" {
		dataHome = filepath.Join(home, ".local", "share")
	}
	cacheHome := os.Getenv("XDG_CACHE_HOME")
	if cacheHome == "" {
		cacheHome = filepath.Join(home, ".cache")
	}

	return Paths{
		ConfigDir: filepath.Join(configHome, appDirName),
		DataDir:   filepath.Join(dataHome, appDirName),
		CacheDir:  filepath.Join(cacheHome, appDirName),
	}, nil
}

// errNoHome is returned when the process has no usable home directory.
var errNoHome = errString("cannot resolve home directory for XDG paths")

type errString string

func (e errString) Error() string { return string(e) }
