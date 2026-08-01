#!/bin/sh
# Lab entrypoint: ensure shared RSA key exists, then exec authlab subcommand.
# LAB ONLY — disposable keys written under LAB_KEYS_DIR (compose volume).
set -eu

KEYS_DIR="${LAB_KEYS_DIR:-/lab-keys}"
mkdir -p "$KEYS_DIR"

# Pre-touch key material via a short-lived keygen so all services share modulus.
# authlab LoadOrGenerateKey is also called by each subcommand; race is ok —
# first writer wins, others reload.
if [ ! -f "$KEYS_DIR/private.pem" ]; then
	# Generate by invoking oidc briefly is heavy; use a tiny Go-free approach:
	# authlab itself generates on first LoadOrGenerateKey. Concurrent starts
	# may race; compose depends_on + restart handles rare failures.
	:
fi

# args: subcommand + optional flags (from compose command:)
if [ "$#" -eq 0 ]; then
	set -- oidc
fi
exec /usr/local/bin/authlab "$@"
