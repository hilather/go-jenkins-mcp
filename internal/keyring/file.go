package keyring

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// EnvKeyringFile, when set to an absolute or relative path, selects the
// headless file keyring backend for this process (CI/smoke only residual).
// Secrets are stored under mode 0600. Prefer OS Secret Service for pilot/
// production operators — never commit this file or put its path in git.
const EnvKeyringFile = "JENKINS_MCP_KEYRING_FILE"

// FileBackend is a process-local secret store backed by a single JSON file.
// Not multi-user secure storage; intended for headless CI without Secret Service.
type FileBackend struct {
	path string
	mu   sync.Mutex
}

// NewFileBackend returns a file-backed store at path (created on first Set).
func NewFileBackend(path string) (*FileBackend, error) {
	path = filepath.Clean(path)
	if path == "" || path == "." {
		return nil, errors.New("keyring: file path is required")
	}
	return &FileBackend{path: path}, nil
}

// OpenFromEnviron returns a FileBackend when EnvKeyringFile is set, else nil, nil.
func OpenFromEnviron() (*FileBackend, error) {
	p := os.Getenv(EnvKeyringFile)
	if p == "" {
		return nil, nil
	}
	return NewFileBackend(p)
}

type fileStore map[string]map[string]string // service -> user -> secret

func (f *FileBackend) load() (fileStore, error) {
	data, err := os.ReadFile(f.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fileStore{}, nil
		}
		return nil, err
	}
	if len(data) == 0 {
		return fileStore{}, nil
	}
	var m fileStore
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = fileStore{}
	}
	return m, nil
}

func (f *FileBackend) save(m fileStore) error {
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	// Unpredictable O_EXCL temp in the same directory: a pre-planted symlink at
	// a guessed <path>.tmp must not receive the secrets write (shared-dir CI
	// pattern). CreateTemp uses mode 0600 and fails rather than following links.
	tmp, err := os.CreateTemp(dir, ".keyring-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, f.path)
}

// Set implements Backend.
func (f *FileBackend) Set(service, user, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return err
	}
	if m[service] == nil {
		m[service] = map[string]string{}
	}
	m[service][user] = password
	return f.save(m)
}

// Get implements Backend.
func (f *FileBackend) Get(service, user string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return "", err
	}
	svc, ok := m[service]
	if !ok {
		return "", ErrNotFound
	}
	v, ok := svc[user]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// Delete implements Backend.
func (f *FileBackend) Delete(service, user string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, err := f.load()
	if err != nil {
		return err
	}
	svc, ok := m[service]
	if !ok {
		return ErrNotFound
	}
	if _, ok := svc[user]; !ok {
		return ErrNotFound
	}
	delete(svc, user)
	if len(svc) == 0 {
		delete(m, service)
	}
	return f.save(m)
}
