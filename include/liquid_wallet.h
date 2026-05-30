#pragma once

#include <stdbool.h>
#include <stdint.h>

// FFI surface for confidential L-BTC wallet (PR 1).
// Modeled exactly on floresta_bitassets_wallet.h patterns.
// Used by scripts/build-liquid-wallet-mobile.sh to package into liquid_wallet.xcframework.

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
