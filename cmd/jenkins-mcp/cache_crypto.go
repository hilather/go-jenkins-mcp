package main

import (
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/keyring"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
	"github.com/simonfxr/go-jenkins-mcp/internal/store"
	storecrypto "github.com/simonfxr/go-jenkins-mcp/internal/store/crypto"
)

// loadProfileFrameCrypto resolves optional ARC-009 AEAD keys for a profile.
// Fail closed when encryption is required (profile flag or env) but the write
// key is missing from the keyring.
func loadProfileFrameCrypto(p *profile.Profile) (*store.FrameCrypto, error) {
	if p == nil {
		return nil, nil
	}
	enabled := p.EffectiveCacheEncryption()
	if !enabled {
		return nil, nil
	}
	ver := p.CacheKeyVersion
	if ver < 1 {
		return nil, apperr.New(apperr.CodeAuthentication,
			"cache encryption required but cacheKeyVersion is unset (run: jenkins-mcp cache key init --profile <id>)")
	}
	return loadFrameCryptoFromKeyring(keyringStore(), string(p.ID), ver)
}

func loadFrameCryptoFromKeyring(kr *keyring.Store, profileID string, writeVersion int) (*store.FrameCrypto, error) {
	if kr == nil {
		return nil, apperr.New(apperr.CodeAuthentication,
			"cache encryption required but keyring is not available")
	}
	if writeVersion < 1 {
		return nil, apperr.New(apperr.CodeAuthentication,
			"cache encryption required but cacheKeyVersion is unset")
	}
	mat, err := kr.GetCacheKey(profileID, writeVersion)
	if err != nil {
		return nil, err
	}
	env := &storecrypto.Envelope{
		Enabled: true,
		Write: storecrypto.Key{
			Version:  writeVersion,
			Material: mat,
		},
	}
	if writeVersion > 1 {
		if prevMat, err := kr.GetCacheKey(profileID, writeVersion-1); err == nil {
			prev := storecrypto.Key{Version: writeVersion - 1, Material: prevMat}
			env.Prev = &prev
		}
		// Missing N-1 is OK (rotation lite; frames sealed with N-1 stay readable
		// only while N-1 remains in the keyring).
	}
	return store.NewFrameCrypto(env)
}
