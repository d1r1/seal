#!/usr/bin/env bash
# Debug build of both binaries for a hand check: `.build/debug/seal` with `seal-frost` next to it, which is
# where Seal looks for the helper. Point a scratch repository's gpg.ssh.program at .build/debug/seal.
set -euo pipefail
cd "$(dirname "$0")/.."
swift build
(cd frost && cargo build --release --quiet)
install -m 755 frost/target/release/seal-frost .build/debug/seal-frost
echo "built .build/debug/seal and .build/debug/seal-frost"
