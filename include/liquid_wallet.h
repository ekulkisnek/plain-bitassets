#pragma once

#include <stdbool.h>
#include <stdint.h>

// FFI surface for confidential L-BTC wallet (PR 1).
// Modeled exactly on floresta_bitassets_wallet.h patterns.
// Used by scripts/build-liquid-wallet-mobile.sh to package into liquid_wallet.xcframework.
//
// SAFETY CONTRACT (see also mobile_ffi.rs module docs):
// - Caller MUST serialize all calls on a given handle (one at a time).
// - Free every returned char* (on ok or !ok) via liquid_wallet_string_free.
// - Exactly one free per open handle; use-after-free is UB.
// - Input strings need only live for the FFI call duration.
// - demo_ct paths are DEMO ONLY (no real value CT yet).
// Reentrancy / concurrent use on handle = UB.

typedef struct {
  bool ok;
  char *value;
} FfiResult;

void liquid_wallet_string_free(char *value);

FfiResult liquid_wallet_open(const char *config_json);
void liquid_wallet_free(uintptr_t handle);

FfiResult liquid_wallet_get_new_address(uintptr_t handle);
FfiResult liquid_wallet_info(uintptr_t handle);
FfiResult liquid_wallet_sync(uintptr_t handle);
FfiResult liquid_wallet_list_utxos(uintptr_t handle);
FfiResult liquid_wallet_get_balance(uintptr_t handle, const char *asset_id);
FfiResult liquid_wallet_transfer(uintptr_t handle, const char *params_json);
