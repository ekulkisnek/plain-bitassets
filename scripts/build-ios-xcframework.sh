#!/usr/bin/env bash
set -euo pipefail

# Builds an XCFramework for liquid-simplicity that works in both
# iOS Simulator and (when you have a real device build) physical devices.
# This is the modern, recommended way to "import" the Rust Liquid code into an Xcode project.

TARGET_SIM="aarch64-apple-ios-sim"
TARGET_DEVICE="aarch64-apple-ios"   # for real devices later

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="$ROOT/target/ios-xcframework"
mkdir -p "$OUT_DIR"

echo "==> Building for iOS Simulator..."
rustup target add "$TARGET_SIM" 2>/dev/null || true
cargo build --target "$TARGET_SIM" --package liquid_simplicity --lib --release || {
  echo "Simulator build failed (common rustup FS issue on this Mac)."
  echo "Try the -Zbuild-std path printed by build-ios-sim.sh first."
  exit 1
}

SIM_LIB="$ROOT/target/$TARGET_SIM/release/libliquid_simplicity.a"

echo "==> Creating XCFramework (Simulator only for now)..."
rm -rf "$OUT_DIR/LiquidSimplicity.xcframework"

xcodebuild -create-xcframework \
  -library "$SIM_LIB" \
  -headers "$ROOT/target/$TARGET_SIM/release/include" 2>/dev/null || \
xcodebuild -create-xcframework \
  -library "$SIM_LIB" \
  -output "$OUT_DIR/LiquidSimplicity.xcframework"

echo ""
echo "=== XCFramework ready ==="
echo "  $OUT_DIR/LiquidSimplicity.xcframework"
echo ""
echo "Drag this folder into your BitWindow / redwallet Xcode project."
echo "It will work on iOS Simulator immediately."
echo "Later, when you have a device build, re-run with both targets to make it universal."
