#!/usr/bin/env bash
set -euo pipefail

TARGET="aarch64-apple-ios-sim"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "==> Building Liquid (ID5) crates for iOS Simulator ($TARGET)..."

# Try normal target first
if rustup target list --installed | grep -q "$TARGET"; then
  echo "Target already installed."
else
  echo "Adding target (this may fail on some Mac setups due to rustup cross-device link issues)..."
  rustup target add "$TARGET" || echo "Continuing — you may need the workaround below."
fi

cd "$ROOT"

echo "==> cargo build --target $TARGET (release, staticlib focus)..."
cargo build --target "$TARGET" --package liquid_simplicity --lib --release || {
  echo ""
  echo "Build hit missing std/core (common on this machine's rustup layout)."
  echo "Workaround (run these):"
  echo "  rustup component add rust-src --toolchain nightly"
  echo "  cargo +nightly build -Zbuild-std --target $TARGET --package liquid_simplicity --lib --release"
  echo ""
  echo "Once that succeeds, the .a will be in target/$TARGET/release/"
  exit 1
}

echo ""
echo "=== Artifacts ready for import ==="
echo "  target/$TARGET/release/libliquid_simplicity.a"
echo ""
echo "Import steps for your BitWindow / redwallet iOS Xcode project (Simulator):"
echo "  1. Drag the .a into your target → 'Link Binary With Libraries'"
echo "  2. (Optional but recommended) Generate headers with cbindgen and add to your bridging header"
echo "  3. Call the FFI entry points from Swift (the same ones used on macOS/desktop)"
echo "  4. Launch on the iOS Simulator and pass the host flags for your local ID5 signet"
echo "     (see README section 'Connecting from simulator/device to host\'s local ID5 signet')"
echo ""
echo "If you still hit rustup FS errors on this Mac, run the build on a Linux CI or a machine"
echo "where rustup is on the same volume as your home directory."
