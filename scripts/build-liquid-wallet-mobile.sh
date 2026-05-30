#!/usr/bin/env bash
set -euo pipefail

# Build script for confidential L-BTC (liquid-simplicity) mobile FFI libs.
# Modeled *exactly* on floresta-bitassets/scripts/build-bitassets-wallet-mobile.sh
# (same target list, cargo ndk logic, xcframework packaging, rustup target add).
# Produces liquid_simplicity staticlib/cdylib + packages liquid_wallet.xcframework
# using the header from ./include/liquid_wallet.h .
#
# Usage: ./scripts/build-liquid-wallet-mobile.sh [target...]
# If no args: builds the standard mobile targets (ios + android).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="liquid_simplicity"
LIB_NAME="liquid_simplicity"
TARGETS=("$@")

if [[ ${#TARGETS[@]} -eq 0 ]]; then
  TARGETS=(
    aarch64-apple-ios
    aarch64-apple-ios-sim
    aarch64-linux-android
    armv7-linux-androideabi
    x86_64-linux-android
  )
fi

for target in "${TARGETS[@]}"; do
  rustup target add "$target"
  case "$target" in
    aarch64-linux-android)
      (cd "$ROOT_DIR" && cargo ndk -t arm64-v8a build -p "$CRATE" --release)
      ;;
    armv7-linux-androideabi)
      (cd "$ROOT_DIR" && cargo ndk -t armeabi-v7a build -p "$CRATE" --release)
      ;;
    i686-linux-android)
      (cd "$ROOT_DIR" && cargo ndk -t x86 build -p "$CRATE" --release)
      ;;
    x86_64-linux-android)
      (cd "$ROOT_DIR" && cargo ndk -t x86_64 build -p "$CRATE" --release)
      ;;
    *)
      cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p "$CRATE" --release --target "$target"
      ;;
  esac
done

echo "Built $CRATE for: ${TARGETS[*]}"

if command -v xcodebuild >/dev/null 2>&1; then
  ios_args=()
  for target in "${TARGETS[@]}"; do
    case "$target" in
      aarch64-apple-ios|aarch64-apple-ios-sim|x86_64-apple-ios)
        lib="$ROOT_DIR/target/$target/release/lib$LIB_NAME.a"
        if [[ -f "$lib" ]]; then
          ios_args+=("-library" "$lib" "-headers" "$ROOT_DIR/include")
        fi
        ;;
    esac
  done

  if [[ ${#ios_args[@]} -gt 0 ]]; then
    rm -rf "$ROOT_DIR/target/liquid_wallet.xcframework"
    xcodebuild -create-xcframework "${ios_args[@]}" -output "$ROOT_DIR/target/liquid_wallet.xcframework" >/dev/null
    echo "Packaged target/liquid_wallet.xcframework"
  fi
fi
