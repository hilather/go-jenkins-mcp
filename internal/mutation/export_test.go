package mutation

// ResetConfirmCooldownForTest clears the process live confirm cooldown so tests
// that leave SetConfirmCooldown state do not leak into parallel NewManager(0)
// cases (unset → DefaultConfirmCooldown).
func ResetConfirmCooldownForTest() {
	liveConfirmCooldownNanos.Store(0)
}

// ResetMaxPreviewsPerMinuteForTest clears the process live Preview rate so
// NewManager(Config{MaxPreviewsPerMinute: 0}) falls back to DefaultMaxPreviewsPerMinute.
// Tests that call SetMaxPreviewsPerMinute must defer this (or re-Set) to avoid
// racing other package tests that rely on unset process live.
func ResetMaxPreviewsPerMinuteForTest() {
	processMaxPreviewsPerMinute.Store(0)
}

// ResetTokenTTLForTest clears the process live confirmation token TTL so tests
// that leave SetTokenTTL state do not leak into parallel NewManager(TTL≤0)
// cases (unset → DefaultTokenTTL).
func ResetTokenTTLForTest() {
	liveTokenTTLNanos.Store(0)
}
