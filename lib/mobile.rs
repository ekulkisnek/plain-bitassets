// SPDX-License-Identifier: MIT OR Apache-2.0

use std::collections::HashMap;
use std::fs;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use bech32::Hrp;
use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv};
use elements::{Address as ElementsAddress, AddressParams};
use elements_miniscript::descriptor::checksum::desc_checksum;
use elements_miniscript::slip77::MasterBlindingKey;
use lwk_common::Signer as LwkSigner;
use lwk_signer::SwSigner;
use lwk_wollet::elements::AssetId as LwkAssetId;
use lwk_wollet::{
    ElectrumClient, ElectrumUrl, ElementsNetwork, UnvalidatedRecipient, Wollet,
    WolletBuilder, WolletDescriptor, blocking::BlockchainBackend,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::AsyncReadExt as _;

use crate::elements_rpc::ElementsRpc;
use crate::types::{
    Address as SidechainAddress, AuthorizedTransaction, FilledOutput,
    FilledOutputContent, InPoint, OutPoint, Output, PointedOutput, Transaction,
};
use crate::wallet::Wallet;

const LIQUID_QUIC_ALPN: &[u8] = b"liquid-quic-v1";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiquidWalletConfig {
    pub path: PathBuf,
    #[serde(default, alias = "walletMode", alias = "mode")]
    pub wallet_mode: Option<String>,
    #[serde(default)]
    pub rpc_url: String,
    #[serde(default)]
    pub lite_wallet_rpc_url: Option<String>,
    #[serde(default, alias = "quicUrl", alias = "liquidLiteWalletQuicUrl")]
    pub liquid_lite_wallet_quic_url: Option<String>,
    #[serde(default)]
    pub electrum_url: Option<String>,
    #[serde(default)]
    pub seed_hex: Option<String>,
    #[serde(default)]
    pub create: bool,
    #[serde(default = "default_persist_seed")]
    pub persist_seed: bool,
}

fn default_persist_seed() -> bool {
    false
}

fn liquid_wallet_mode(
    requested: Option<&str>,
    rpc_url: &str,
    electrum_url: Option<&str>,
    lite_wallet_rpc_url: Option<&str>,
    liquid_lite_wallet_quic_url: Option<&str>,
) -> Result<LiquidWalletMode, String> {
    let requested = requested.unwrap_or("").trim().to_ascii_lowercase();
    match requested.as_str() {
        "lwk" | "liquid-wallet-kit" | "electrum" | "phone-local-electrum" => {
            return Ok(LiquidWalletMode::Lwk);
        }
        "utreexo"
        | "lite-wallet"
        | "sidechain-lite-wallet"
        | "quic"
        | "lite-wallet-quic" => {
            return Ok(LiquidWalletMode::Utreexo);
        }
        "elements-rpc" | "jsonrpc" | "rpc" => {
            return Ok(LiquidWalletMode::ElementsRpc);
        }
        "local" | "local-only" | "embedded-local" => {
            return Ok(LiquidWalletMode::LocalOnly);
        }
        "" => {}
        other => {
            return Err(format!("unsupported Liquid wallet mode '{other}'"));
        }
    }

    if liquid_lite_wallet_quic_url.is_some() || lite_wallet_rpc_url.is_some() {
        return Ok(LiquidWalletMode::Utreexo);
    }
    if electrum_url.is_some() {
        return Ok(LiquidWalletMode::Lwk);
    }
    if !rpc_url.trim().is_empty() {
        return Ok(LiquidWalletMode::ElementsRpc);
    }
    Ok(LiquidWalletMode::LocalOnly)
}

#[derive(Debug, Serialize, Deserialize, Default)]
struct LiquidWalletPersisted {
    addresses: Vec<String>,
    next_index: u32,
    #[serde(default)]
    last_tip_hash: Option<String>,
    seed_hex: String,
    #[serde(default)]
    version: u32,
}

#[derive(Debug, Deserialize)]
struct LiteWalletUpdate {
    tip_hash: Option<String>,
    tip_height: Option<u32>,
    #[serde(default)]
    utreexo_leaf_count: u64,
    #[serde(default)]
    utreexo_roots: Vec<String>,
    created_utxos: Vec<PointedOutput<FilledOutputContent>>,
    spent_outpoints: Vec<OutPoint>,
    mempool_created_utxos: Vec<PointedOutput>,
    mempool_spent_outpoints: Vec<OutPoint>,
    transactions: Vec<Transaction>,
    #[serde(default)]
    proof_refs: Vec<Value>,
    #[serde(default)]
    utreexo_proofs: Vec<Value>,
}

pub struct EmbeddedLiquidWallet {
    pub(crate) wallet_mode: LiquidWalletMode,
    pub(crate) rpc: Option<ElementsRpc>,
    pub(crate) lite_wallet_rpc_url: Option<String>,
    pub(crate) liquid_lite_wallet_quic_url: Option<String>,
    pub(crate) electrum_url: Option<String>,
    pub(crate) state_path: PathBuf,
    pub(crate) wallet: Option<Wallet>,
    pub(crate) master_seed: Option<[u8; 64]>,
    pub(crate) addresses: Vec<String>,
    pub(crate) next_index: u32,
    pub(crate) last_tip_hash: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LiquidWalletMode {
    Lwk,
    Utreexo,
    ElementsRpc,
    LocalOnly,
}

impl EmbeddedLiquidWallet {
    pub fn open(config: LiquidWalletConfig) -> Result<Self, String> {
        let master_seed: Option<[u8; 64]> = if let Some(hex) = &config.seed_hex
        {
            if hex.len() != 128 {
                return Err(
                    "seed_hex must be exactly 128 hex chars (64 bytes)".into(),
                );
            }
            let mut bytes = [0u8; 64];
            for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
                let s =
                    std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
                bytes[i] =
                    u8::from_str_radix(s, 16).map_err(|e| e.to_string())?;
            }
            Some(bytes)
        } else {
            None
        };

        let state_path = config.path.clone();
        if let Some(parent) = state_path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }

        let mut persisted: LiquidWalletPersisted = if state_path.exists() {
            let content =
                fs::read_to_string(&state_path).map_err(|e| e.to_string())?;
            serde_json::from_str(&content)
                .map_err(|e| format!("failed to deserialize wallet state at {:?}: {} (re-create required)", state_path, e))?
        } else if config.create {
            LiquidWalletPersisted::default()
        } else {
            return Err(format!(
                "wallet file not found at {:?} (create=false)",
                state_path
            ));
        };

        if !config.persist_seed {
            persisted.seed_hex = String::new();
        } else if let Some(seed) = &config.seed_hex {
            persisted.seed_hex = seed.clone();
        }

        let json = serde_json::to_string_pretty(&persisted)
            .map_err(|e| e.to_string())?;
        atomic_write(&state_path, &json)?;

        let rpc = if config.rpc_url.trim().is_empty() {
            None
        } else {
            Some(
                ElementsRpc::new(&config.rpc_url, None)
                    .map_err(|e| format!("ElementsRpc init failed: {}", e))?,
            )
        };
        let lite_wallet_rpc_url = config.lite_wallet_rpc_url.and_then(|url| {
            (!url.trim().is_empty()).then(|| url.trim().to_string())
        });
        let liquid_lite_wallet_quic_url =
            config.liquid_lite_wallet_quic_url.and_then(|url| {
                (!url.trim().is_empty()).then(|| url.trim().to_string())
            });
        let electrum_url = config.electrum_url.and_then(|url| {
            (!url.trim().is_empty()).then(|| url.trim().to_string())
        });
        let wallet_mode = liquid_wallet_mode(
            config.wallet_mode.as_deref(),
            config.rpc_url.as_str(),
            electrum_url.as_deref(),
            lite_wallet_rpc_url.as_deref(),
            liquid_lite_wallet_quic_url.as_deref(),
        )?;
        let wallet = if wallet_mode == LiquidWalletMode::Utreexo {
            let wallet_path = state_path
                .parent()
                .unwrap_or_else(|| std::path::Path::new("."))
                .join("wallet.mdb");
            let wallet = match Wallet::new(&wallet_path) {
                Ok(wallet) => wallet,
                Err(first_error) => {
                    drop(fs::remove_dir_all(&wallet_path));
                    Wallet::new(&wallet_path).map_err(|second_error| {
                        format!(
                            "mobile wallet db open failed: {second_error} (after recovery from {first_error})"
                        )
                    })?
                }
            };
            if let Some(seed) = master_seed.as_ref() {
                wallet.set_seed(seed).map_err(|e| {
                    format!("mobile wallet seed setup failed: {e}")
                })?;
            }
            Some(wallet)
        } else {
            None
        };

        Ok(Self {
            wallet_mode,
            rpc,
            lite_wallet_rpc_url,
            liquid_lite_wallet_quic_url,
            electrum_url,
            state_path,
            wallet,
            master_seed,
            addresses: persisted.addresses,
            next_index: persisted.next_index,
            last_tip_hash: persisted.last_tip_hash,
        })
    }

    fn persist(&mut self) -> Result<(), String> {
        let persisted = LiquidWalletPersisted {
            addresses: self.addresses.clone(),
            next_index: self.next_index,
            last_tip_hash: self.last_tip_hash.clone(),
            seed_hex: String::new(),
            version: 0,
        };
        let json = serde_json::to_string_pretty(&persisted)
            .map_err(|e| e.to_string())?;
        atomic_write(&self.state_path, &json)
    }

    fn lite_wallet(&self) -> Result<&Wallet, String> {
        self.wallet.as_ref().ok_or_else(|| {
            "Liquid lite-wallet storage is not configured".to_string()
        })
    }

    fn uses_utreexo_lite_wallet(&self) -> bool {
        self.wallet_mode == LiquidWalletMode::Utreexo
    }

    fn uses_lwk_wallet(&self) -> bool {
        self.wallet_mode == LiquidWalletMode::Lwk
    }

    pub fn get_new_address(&mut self) -> Result<String, String> {
        if self.uses_utreexo_lite_wallet() {
            let address = self
                .lite_wallet()?
                .get_new_address()
                .map_err(|e| format!("mobile lite-wallet address failed: {e}"))?
                .to_string();
            self.addresses.push(address.clone());
            self.next_index += 1;
            self.persist()?;
            return Ok(address);
        }
        if self.uses_lwk_wallet() {
            let wollet = self.lwk_wollet()?;
            let address = wollet
                .address(Some(self.next_index))
                .map_err(|e| format!("LWK address derivation failed: {e}"))?
                .address()
                .to_string();
            self.addresses.push(address.clone());
            self.next_index += 1;
            self.persist()?;
            return Ok(address);
        }
        if self.rpc.is_none() {
            return Err("Liquid wallet needs wallet_mode=lwk with electrum_url for node-free addresses, or wallet_mode=utreexo for sidechain lite-wallet addresses".into());
        }

        let seed = self.master_seed.ok_or_else(|| {
            "no seed available (provide seed_hex at open)".to_string()
        })?;

        let master = Xpriv::new_master(bitcoin::NetworkKind::Test, &seed)
            .map_err(|e| e.to_string())?;

        let addr = derive_next_confidential_address(self.next_index, &master)?;

        self.addresses.push(addr.clone());
        self.next_index += 1;
        self.persist()?;

        Ok(addr)
    }

    pub fn wallet_info_json(&self) -> Result<String, String> {
        Ok(json!({
            "enabled": true,
            "balances": {},
            "address_count": self.addresses.len(),
            "next_index": self.next_index,
            "last_address": self.addresses.last(),
            "mode": if self.uses_utreexo_lite_wallet() && self.liquid_lite_wallet_quic_url.is_some() {
                "sidechain-lite-wallet-quic"
            } else if self.uses_utreexo_lite_wallet() {
                "sidechain-lite-wallet"
            } else if self.uses_lwk_wallet() {
                "lwk-electrum"
            } else if self.wallet_mode == LiquidWalletMode::ElementsRpc {
                "elements-rpc"
            } else {
                "embedded-local"
            },
            "last_tip_hash": self.last_tip_hash,
            "wallet_engine": if self.uses_lwk_wallet() { "liquid-wallet-kit" } else if self.uses_utreexo_lite_wallet() { "utreexo-lite-wallet" } else { "legacy" },
            "note": if self.liquid_lite_wallet_quic_url.is_some() {
                "Sidechain lite-wallet compatibility mode over QUIC: local keys, watched UTXOs, local authorization"
            } else if self.uses_utreexo_lite_wallet() {
                "Sidechain lite-wallet compatibility mode: local keys, watched UTXOs, local authorization, relay submit"
            } else if self.uses_lwk_wallet() {
                "Liquid Wallet Kit light wallet: local signer, LWK descriptor, Electrum scan/broadcast"
            } else if self.wallet_mode == LiquidWalletMode::ElementsRpc {
                "L-BTC confidential primitives compatibility path"
            } else {
                "Phone-local Liquid signer: local confidential address derivation only"
            }
        })
        .to_string())
    }

    pub fn sync_json(&mut self) -> Result<String, String> {
        if self.uses_utreexo_lite_wallet() {
            if let Some(quic_url) = self.liquid_lite_wallet_quic_url.clone() {
                return match self.sync_quic_once(&quic_url) {
                    Ok(info) => Ok(info.to_string()),
                    Err(err) => Err(err),
                };
            }
            return self.sync_lite_wallet_json();
        }
        if self.uses_lwk_wallet() {
            return self.sync_lwk_electrum_json();
        }
        if self.rpc.is_none() {
            return Ok(json!({
                "enabled": true,
                "balances": {},
                "address_count": self.addresses.len(),
                "confirmed_utxo_count": 0,
                "mempool_utxo_count": 0,
                "mode": "embedded-local",
                "note": "Phone-local Liquid signer has no Electrum light backend configured"
            })
            .to_string());
        }
        let rt = get_runtime();
        let rpc = self.rpc.as_ref().ok_or_else(|| {
            "Liquid Elements RPC URL is not configured".to_string()
        })?;
        let height = rt
            .block_on(rpc.getblockcount())
            .map_err(|e| e.to_string())?;
        Ok(json!({
            "height": height,
            "address_count": self.addresses.len(),
            "note": "sync uses ElementsRpc; confidential unblinding stub"
        })
        .to_string())
    }

    fn sync_quic_once(&mut self, quic_url: &str) -> Result<Value, String> {
        let remote = liquid_quic_remote(quic_url)?;
        let addresses = self
            .lite_wallet()?
            .get_addresses()
            .map_err(|e| format!("mobile lite-wallet addresses failed: {e}"))?;
        if addresses.is_empty() {
            return self.wallet_info_json().and_then(|json| {
                serde_json::from_str(&json).map_err(|e| e.to_string())
            });
        }
        let script_hashes: Vec<String> = addresses
            .iter()
            .map(|address| hex::encode(blake3::hash(&address.0).as_bytes()))
            .collect();
        let from_block_hash = self.last_tip_hash.clone();
        let request = json!({
            "type": "subscribe",
            "script_hashes": script_hashes,
            "from_block_hash": from_block_hash,
        });
        let runtime = get_runtime();
        let update = runtime.block_on(async {
            let endpoint = liquid_quic_endpoint(remote)?;
            let connection = endpoint
                .connect(remote, "localhost")
                .map_err(|err| format!("QUIC connect setup failed: {err}"))?
                .await
                .map_err(|err| format!("QUIC connect failed: {err}"))?;
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|err| format!("QUIC stream open failed: {err}"))?;
            let mut request_bytes =
                serde_json::to_vec(&request).map_err(|e| e.to_string())?;
            request_bytes.push(b'\n');
            send.write_all(&request_bytes)
                .await
                .map_err(|err| format!("QUIC subscribe write failed: {err}"))?;
            send.finish().map_err(|err| {
                format!("QUIC subscribe finish failed: {err}")
            })?;

            let mut buffer = Vec::<u8>::new();
            loop {
                let chunk = tokio::time::timeout(
                    Duration::from_secs(15),
                    recv.read_buf(&mut buffer),
                )
                .await
                .map_err(|_| "QUIC lite-wallet sync timed out".to_string())?
                .map_err(|err| format!("QUIC read failed: {err}"))?;
                if chunk == 0 && buffer.is_empty() {
                    return Err("QUIC lite-wallet stream closed".to_string());
                }
                while let Some(newline) =
                    buffer.iter().position(|byte| *byte == b'\n')
                {
                    let line = buffer.drain(..=newline).collect::<Vec<_>>();
                    let line = &line[..line.len().saturating_sub(1)];
                    if line.is_empty() {
                        continue;
                    }
                    return liquid_quic_update_from_message(line);
                }
                if chunk == 0 {
                    if !buffer.is_empty() {
                        return liquid_quic_update_from_message(&buffer);
                    }
                    return Err("QUIC lite-wallet stream ended without update"
                        .to_string());
                }
            }
        })?;
        self.apply_lite_wallet_update(&update)?;
        self.last_tip_hash = update.tip_hash.clone();
        self.persist()?;
        let balance = self
            .lite_wallet()?
            .get_bitcoin_balance()
            .map_err(|e| format!("mobile lite-wallet balance failed: {e}"))?;
        Ok(json!({
            "enabled": true,
            "balances": { "bitcoin": balance.available.to_sat() },
            "confirmed_utxo_count": self.lite_wallet()?.get_utxos().map_err(|e| e.to_string())?.len(),
            "sidechainHeight": update.tip_height,
            "last_tip_hash": update.tip_hash,
            "last_tip_height": update.tip_height,
            "utreexo_leaf_count": update.utreexo_leaf_count,
            "utreexo_roots": update.utreexo_roots,
            "utreexo_proof_count": update.utreexo_proofs.len(),
            "proof_ref_count": update.proof_refs.len(),
            "mode": "lite-wallet-quic"
        }))
    }

    pub fn list_utxos_json(&self) -> Result<String, String> {
        if self.uses_utreexo_lite_wallet() {
            let utxos = self.lite_wallet()?.get_utxos().map_err(|e| {
                format!("mobile lite-wallet list UTXOs failed: {e}")
            })?;
            let pointed: Vec<_> = utxos
                .into_iter()
                .map(|(outpoint, output)| PointedOutput { outpoint, output })
                .collect();
            return serde_json::to_string(&pointed).map_err(|e| e.to_string());
        }
        if self.uses_lwk_wallet() {
            return self.list_lwk_utxos_json();
        }
        if self.rpc.is_none() {
            return Ok("[]".to_string());
        }
        Ok(json!({ "addresses": self.addresses, "utxos": [] }).to_string())
    }

    pub fn get_balance_json(
        &self,
        _asset_id: Option<&str>,
    ) -> Result<String, String> {
        if self.uses_utreexo_lite_wallet() {
            let balance =
                self.lite_wallet()?.get_bitcoin_balance().map_err(|e| {
                    format!("mobile lite-wallet balance failed: {e}")
                })?;
            return Ok(json!({
                "bitcoin": balance.available.to_sat(),
                "confirmed": balance.available.to_sat(),
                "total": balance.total.to_sat(),
                "mode": "lite-wallet"
            })
            .to_string());
        }
        if self.uses_lwk_wallet() {
            let balances = self.lwk_balance_map()?;
            let policy = self.lwk_network().policy_asset().to_string();
            return Ok(json!({
                "confirmed": balances.get(&policy).copied().unwrap_or(0),
                "bitcoin": balances.get(&policy).copied().unwrap_or(0),
                "balances": balances,
                "mode": "lwk-electrum",
                "wallet_engine": "liquid-wallet-kit"
            })
            .to_string());
        }
        if self.rpc.is_none() {
            return Ok(json!({
                "confirmed": 0,
                "bitcoin": 0,
                "mode": "embedded-local"
            })
            .to_string());
        }
        let rt = get_runtime();
        let rpc = self.rpc.as_ref().ok_or_else(|| {
            "Liquid Elements RPC URL is not configured".to_string()
        })?;
        let amount =
            rt.block_on(rpc.getbalance()).map_err(|e| e.to_string())?;
        Ok(json!({
            "asset": "lbtc",
            "sats": amount.to_sat(),
            "note": "L-BTC via ElementsRpc (confidential amounts unblinded in Rust only)"
        })
        .to_string())
    }

    pub fn transfer_json(
        &mut self,
        params_json: &str,
    ) -> Result<String, String> {
        if self.uses_utreexo_lite_wallet() {
            return self.transfer_lite_wallet_json(params_json);
        }
        if self.uses_lwk_wallet() {
            return self.transfer_lwk_electrum_json(params_json);
        }
        if self.rpc.is_none() {
            return Err("phone-local Liquid send requires wallet_mode=lwk and a Liquid Electrum light backend; local signer/address creation is available".into());
        }
        #[derive(Deserialize)]
        struct Params {
            #[serde(alias = "destinationAddress")]
            destination_address: String,
            amount: u64,
            #[serde(default, alias = "feeSats")]
            _fee_sats: Option<u64>,
            #[serde(default)]
            demo_ct: bool,
        }
        let _params: Params = serde_json::from_str(params_json)
            .map_err(|e| format!("bad transfer params: {}", e))?;

        if !_params.demo_ct {
            return Err("skeleton: full CT transfer not implemented (use demo_ct:true only for the demo_pedersen primitive exercise)".into());
        }

        let demo = self.demo_pedersen_rangeproof(1000);

        Ok(json!({
            "txid": "0000000000000000000000000000000000000000000000000000000000000000",
            "skeleton": true,
            "destination": _params.destination_address,
            "amount": _params.amount,
            "demo_ct": demo,
            "note": "L-BTC transfer skeleton (PR 1). Full blinding factors, range proofs, signing, and broadcast in later PR.",
            "warning": "DEMO ONLY - NOT A REAL INTEGRATED CONFIDENTIAL TX / BLINDING / RANGEPROOF ON REAL OUTPUTS. For test vectors only."
        })
        .to_string())
    }

    fn sync_lite_wallet_json(&mut self) -> Result<String, String> {
        let addresses = self
            .lite_wallet()?
            .get_addresses()
            .map_err(|e| format!("mobile lite-wallet addresses failed: {e}"))?;
        if addresses.is_empty() {
            return Ok(json!({
                "enabled": true,
                "balances": { "bitcoin": 0 },
                "address_count": 0,
                "mode": "lite-wallet"
            })
            .to_string());
        }
        let script_hashes: Vec<String> = addresses
            .iter()
            .map(|address| hex::encode(blake3::hash(&address.0).as_bytes()))
            .collect();
        let update = self.lite_wallet_update(script_hashes)?;
        self.apply_lite_wallet_update(&update)?;
        self.last_tip_hash = update.tip_hash.clone();
        self.persist()?;
        let balance = self
            .lite_wallet()?
            .get_bitcoin_balance()
            .map_err(|e| format!("mobile lite-wallet balance failed: {e}"))?;
        Ok(json!({
            "enabled": true,
            "balances": { "bitcoin": balance.available.to_sat() },
            "confirmed_utxo_count": self.lite_wallet()?.get_utxos().map_err(|e| e.to_string())?.len(),
            "sidechainHeight": update.tip_height,
            "last_tip_hash": update.tip_hash,
            "last_tip_height": update.tip_height,
            "utreexo_leaf_count": update.utreexo_leaf_count,
            "utreexo_roots": update.utreexo_roots,
            "utreexo_proof_count": update.utreexo_proofs.len(),
            "proof_ref_count": update.proof_refs.len(),
            "mode": "lite-wallet"
        })
        .to_string())
    }

    fn transfer_lite_wallet_json(
        &mut self,
        params_json: &str,
    ) -> Result<String, String> {
        #[derive(Deserialize)]
        struct Params {
            #[serde(alias = "destinationAddress")]
            destination_address: String,
            amount: u64,
            #[serde(default, alias = "feeSats")]
            fee_sats: Option<u64>,
            #[serde(default)]
            memo: Option<String>,
        }
        let params: Params = serde_json::from_str(params_json)
            .map_err(|e| format!("bad transfer params: {e}"))?;
        self.sync_json()?;
        let destination: SidechainAddress = params
            .destination_address
            .parse()
            .map_err(|e| format!("bad destination address: {e}"))?;
        let memo = params
            .memo
            .map(|memo| {
                hex::decode(memo).map_err(|e| format!("bad memo hex: {e}"))
            })
            .transpose()?;
        let tx = self
            .lite_wallet()?
            .create_transfer(
                destination,
                bitcoin::Amount::from_sat(params.amount),
                bitcoin::Amount::from_sat(params.fee_sats.unwrap_or(0)),
                memo,
            )
            .map_err(|e| {
                format!("mobile lite-wallet create transfer failed: {e}")
            })?;
        let txid = tx.txid();
        let authorized = self
            .lite_wallet()?
            .authorize(tx)
            .map_err(|e| format!("mobile lite-wallet authorize failed: {e}"))?;
        self.submit_authorized_transaction(&authorized)?;
        Ok(json!({
            "txid": txid.to_string(),
            "mode": if self.liquid_lite_wallet_quic_url.is_some() { "lite-wallet-quic" } else { "lite-wallet" },
            "submitted": true
        })
        .to_string())
    }

    fn lite_wallet_update(
        &self,
        script_hashes: Vec<String>,
    ) -> Result<LiteWalletUpdate, String> {
        let url = self.lite_wallet_rpc_url.as_ref().ok_or_else(|| {
            "Liquid lite-wallet RPC URL is not configured".to_string()
        })?;
        let params = vec![
            json!(script_hashes),
            self.last_tip_hash
                .as_ref()
                .map(|tip| json!(tip))
                .unwrap_or(Value::Null),
        ];
        self.json_rpc(url, "get_lite_wallet_update", params)
    }

    fn submit_authorized_transaction(
        &self,
        authorized: &AuthorizedTransaction,
    ) -> Result<(), String> {
        let bytes = borsh::to_vec(authorized).map_err(|e| {
            format!("authorized transaction encode failed: {e}")
        })?;
        let hex_borsh_authorized_tx = hex::encode(bytes);
        if let Some(quic_url) = self.liquid_lite_wallet_quic_url.as_ref() {
            return self.submit_authorized_transaction_quic(
                quic_url,
                &hex_borsh_authorized_tx,
            );
        }
        let url = self.lite_wallet_rpc_url.as_ref().ok_or_else(|| {
            "Liquid lite-wallet RPC URL is not configured".to_string()
        })?;
        drop(self.json_rpc::<serde_json::Value>(
            url,
            "submit_authorized_transaction",
            vec![json!(hex_borsh_authorized_tx)],
        )?);
        Ok(())
    }

    fn submit_authorized_transaction_quic(
        &self,
        quic_url: &str,
        hex_borsh_authorized_tx: &str,
    ) -> Result<(), String> {
        let remote = liquid_quic_remote(quic_url)?;
        let request = json!({
            "type": "submit_authorized_transaction",
            "hex_borsh_authorized_tx": hex_borsh_authorized_tx,
        });
        let runtime = get_runtime();
        runtime.block_on(async {
            let endpoint = liquid_quic_endpoint(remote)?;
            let connection = endpoint
                .connect(remote, "localhost")
                .map_err(|err| {
                    format!("QUIC submit connect setup failed: {err}")
                })?
                .await
                .map_err(|err| format!("QUIC submit connect failed: {err}"))?;
            let (mut send, mut recv) =
                connection.open_bi().await.map_err(|err| {
                    format!("QUIC submit stream open failed: {err}")
                })?;
            let mut request_bytes =
                serde_json::to_vec(&request).map_err(|e| e.to_string())?;
            request_bytes.push(b'\n');
            send.write_all(&request_bytes)
                .await
                .map_err(|err| format!("QUIC submit write failed: {err}"))?;
            send.finish()
                .map_err(|err| format!("QUIC submit finish failed: {err}"))?;

            let mut response = Vec::<u8>::new();
            tokio::time::timeout(
                Duration::from_secs(15),
                recv.read_to_end(64 * 1024),
            )
            .await
            .map_err(|_| "QUIC submit timed out".to_string())?
            .map(|bytes| response = bytes)
            .map_err(|err| format!("QUIC submit read failed: {err}"))?;
            let message: Value = serde_json::from_slice(response.trim_ascii())
                .map_err(|e| {
                    format!("QUIC submit response decode failed: {e}")
                })?;
            let message_type =
                message.get("type").and_then(Value::as_str).ok_or_else(
                    || "QUIC submit response missing type".to_string(),
                )?;
            match message_type {
                "submitted" => Ok(()),
                "error" => Err(message
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("liquid-simplicity lite-wallet submit error")
                    .to_string()),
                other => {
                    Err(format!("unexpected QUIC submit response type {other}"))
                }
            }
        })
    }

    fn json_rpc<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        method: &str,
        params: Vec<Value>,
    ) -> Result<T, String> {
        let rt = get_runtime();
        rt.block_on(async {
            let body = json!({
                "jsonrpc": "2.0",
                "id": "redwallet-liquid-mobile",
                "method": method,
                "params": params,
            });
            let response = reqwest::Client::new()
                .post(url)
                .json(&body)
                .send()
                .await
                .map_err(|e| format!("lite-wallet RPC request failed: {e}"))?;
            let status = response.status();
            let value: Value = response.json().await.map_err(|e| {
                format!("lite-wallet RPC response parse failed: {e}")
            })?;
            if !status.is_success() {
                return Err(format!("lite-wallet RPC HTTP {status}: {value}"));
            }
            if let Some(error) =
                value.get("error").filter(|error| !error.is_null())
            {
                return Err(format!("lite-wallet RPC error: {error}"));
            }
            serde_json::from_value(
                value.get("result").cloned().unwrap_or(Value::Null),
            )
            .map_err(|e| format!("lite-wallet RPC result decode failed: {e}"))
        })
    }

    fn apply_lite_wallet_update(
        &self,
        update: &LiteWalletUpdate,
    ) -> Result<(), String> {
        let confirmed: HashMap<OutPoint, FilledOutput> = update
            .created_utxos
            .iter()
            .cloned()
            .map(|pointed| (pointed.outpoint, pointed.output))
            .collect();
        if !confirmed.is_empty() {
            self.wallet
                .as_ref()
                .ok_or_else(|| {
                    "Liquid lite-wallet storage is not configured".to_string()
                })?
                .put_utxos(&confirmed)
                .map_err(|e| {
                    format!("mobile lite-wallet put UTXOs failed: {e}")
                })?;
        }
        let mempool: HashMap<OutPoint, Output> = update
            .mempool_created_utxos
            .iter()
            .cloned()
            .map(|pointed| (pointed.outpoint, pointed.output))
            .collect();
        if !mempool.is_empty() {
            self.wallet
                .as_ref()
                .ok_or_else(|| {
                    "Liquid lite-wallet storage is not configured".to_string()
                })?
                .put_unconfirmed_utxos(&mempool)
                .map_err(|e| {
                    format!("mobile lite-wallet put mempool UTXOs failed: {e}")
                })?;
        }
        let spent: Vec<(OutPoint, InPoint)> = update
            .spent_outpoints
            .iter()
            .chain(update.mempool_spent_outpoints.iter())
            .copied()
            .enumerate()
            .map(|(idx, outpoint)| {
                (
                    outpoint,
                    InPoint::Regular {
                        txid: update
                            .transactions
                            .get(idx)
                            .map(Transaction::txid)
                            .unwrap_or_default(),
                        vin: 0,
                    },
                )
            })
            .collect();
        if !spent.is_empty() {
            self.wallet
                .as_ref()
                .ok_or_else(|| {
                    "Liquid lite-wallet storage is not configured".to_string()
                })?
                .spend_utxos(&spent)
                .map_err(|e| {
                    format!("mobile lite-wallet spend UTXOs failed: {e}")
                })?;
        }
        Ok(())
    }

    fn lwk_network(&self) -> ElementsNetwork {
        let policy_asset =
            "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225"
                .parse()
                .expect("redwallet isolated Elements policy asset id is valid");
        ElementsNetwork::ElementsRegtest { policy_asset }
    }

    fn normalize_lwk_recipient_address(
        &self,
        address: &str,
    ) -> Result<String, String> {
        if let Ok(address) = ElementsAddress::parse_with_params(
            address,
            local_sidechain_address_params(),
        ) {
            let normalized = ElementsAddress::from_script(
                &address.script_pubkey(),
                address.blinding_pubkey,
                &AddressParams::ELEMENTS,
            )
            .ok_or_else(|| {
                "phone-local Liquid recipient script is not supported"
                    .to_string()
            })?;
            return Ok(normalized.to_string());
        }
        Ok(address.to_string())
    }

    fn lwk_signer(&self) -> Result<SwSigner, String> {
        let seed = self.master_seed.ok_or_else(|| {
            "phone-local Liquid signer seed is not loaded".to_string()
        })?;
        let xprv = Xpriv::new_master(bitcoin::Network::Testnet, &seed)
            .map_err(|e| {
                format!("phone-local Liquid master key failed: {e}")
            })?;
        Ok(SwSigner::from_xprv(xprv))
    }

    fn lwk_descriptor(&self) -> Result<WolletDescriptor, String> {
        let seed = self.master_seed.ok_or_else(|| {
            "phone-local Liquid signer seed is not loaded".to_string()
        })?;
        let signer = self.lwk_signer()?;
        let path: DerivationPath = "m/84h/1h/0h".parse().map_err(|e| {
            format!("phone-local Liquid descriptor path failed: {e}")
        })?;
        let fingerprint = signer.fingerprint();
        let xpub = signer.derive_xpub(&path).map_err(|e| {
            format!("phone-local Liquid account xpub failed: {e}")
        })?;
        let slip77 = MasterBlindingKey::from_seed(&seed[..]);
        let desc = format!(
            "ct(slip77({slip77}),elwpkh([{fingerprint}/84h/1h/0h]{xpub}/<0;1>/*))"
        );
        let checksum = desc_checksum(&desc).map_err(|e| {
            format!("phone-local Liquid descriptor checksum failed: {e:?}")
        })?;
        let desc = format!("{desc}#{checksum}");
        desc.parse().map_err(|e| {
            format!("phone-local Liquid descriptor parse failed: {e}")
        })
    }

    fn lwk_wollet(&self) -> Result<Wollet, String> {
        let descriptor = self.lwk_descriptor()?;
        let datadir = self
            .state_path
            .parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .join("lwk");
        fs::create_dir_all(&datadir).map_err(|e| {
            format!("phone-local Liquid store setup failed: {e}")
        })?;
        WolletBuilder::new(self.lwk_network(), descriptor)
            .with_legacy_fs_store(&datadir)
            .map_err(|e| format!("phone-local Liquid store open failed: {e}"))?
            .build()
            .map_err(|e| format!("phone-local Liquid wallet open failed: {e}"))
    }

    fn lwk_electrum_client(&self) -> Result<ElectrumClient, String> {
        let url = self.electrum_url.as_ref().ok_or_else(|| {
            "Liquid Electrum URL is not configured".to_string()
        })?;
        let electrum_url: ElectrumUrl = url
            .parse()
            .map_err(|e| format!("bad Liquid Electrum URL '{url}': {e}"))?;
        ElectrumClient::new(&electrum_url)
            .map_err(|e| format!("Liquid Electrum connection failed: {e}"))
    }

    fn sync_lwk_wallet(&self) -> Result<Wollet, String> {
        let mut wollet = self.lwk_wollet()?;
        let mut client = self.lwk_electrum_client()?;
        if let Some(update) = client
            .full_scan_to_index(&wollet, self.next_index.saturating_add(20))
            .map_err(|e| format!("Liquid Electrum scan failed: {e}"))?
        {
            wollet.apply_update(update).map_err(|e| {
                format!("phone-local Liquid update failed: {e}")
            })?;
        }
        Ok(wollet)
    }

    fn lwk_balance_map(&self) -> Result<HashMap<String, u64>, String> {
        let wollet = self.sync_lwk_wallet()?;
        let balance = wollet
            .balance()
            .map_err(|e| format!("phone-local Liquid balance failed: {e}"))?;
        Ok(balance
            .as_ref()
            .iter()
            .map(|(asset, amount)| (asset.to_string(), *amount))
            .collect())
    }

    fn sync_lwk_electrum_json(&mut self) -> Result<String, String> {
        let wollet = self.sync_lwk_wallet()?;
        let balance = wollet
            .balance()
            .map_err(|e| format!("phone-local Liquid balance failed: {e}"))?;
        let utxos = wollet
            .txos()
            .map_err(|e| format!("phone-local Liquid UTXO scan failed: {e}"))?;
        let balances: HashMap<String, u64> = balance
            .as_ref()
            .iter()
            .map(|(asset, amount)| (asset.to_string(), *amount))
            .collect();
        let tip = wollet.tip();
        Ok(json!({
            "enabled": true,
            "balances": balances,
            "confirmed_utxo_count": utxos.iter().filter(|utxo| !utxo.is_spent && utxo.height.is_some()).count(),
            "mempool_utxo_count": utxos.iter().filter(|utxo| !utxo.is_spent && utxo.height.is_none()).count(),
            "last_tip_hash": tip.hash().to_string(),
            "last_tip_height": tip.height(),
            "mode": "phone-local-electrum"
        })
        .to_string())
    }

    fn list_lwk_utxos_json(&self) -> Result<String, String> {
        let wollet = self.sync_lwk_wallet()?;
        let utxos = wollet
            .txos()
            .map_err(|e| format!("phone-local Liquid UTXO list failed: {e}"))?;
        let values: Vec<_> = utxos
            .into_iter()
            .filter(|utxo| !utxo.is_spent)
            .map(|utxo| {
                json!({
                    "txid": utxo.outpoint.txid.to_string(),
                    "vout": utxo.outpoint.vout,
                    "address": utxo.address.to_string(),
                    "assetId": utxo.unblinded.asset.to_string(),
                    "asset_id": utxo.unblinded.asset.to_string(),
                    "amount": utxo.unblinded.value,
                    "confirmed": utxo.height.is_some(),
                    "confidential": true
                })
            })
            .collect();
        serde_json::to_string(&values).map_err(|e| e.to_string())
    }

    fn transfer_lwk_electrum_json(
        &mut self,
        params_json: &str,
    ) -> Result<String, String> {
        #[derive(Deserialize)]
        struct Params {
            #[serde(alias = "destinationAddress")]
            destination_address: String,
            amount: u64,
            #[serde(default, alias = "assetId")]
            asset_id: Option<String>,
        }
        let params: Params = serde_json::from_str(params_json)
            .map_err(|e| format!("bad transfer params: {e}"))?;
        let wollet = self.sync_lwk_wallet()?;
        let asset = params
            .asset_id
            .filter(|asset| !asset.trim().is_empty() && asset != "bitcoin")
            .unwrap_or_else(|| self.lwk_network().policy_asset().to_string());
        let recipient = UnvalidatedRecipient {
            satoshi: params.amount,
            address: self
                .normalize_lwk_recipient_address(&params.destination_address)?,
            asset,
        };
        let wallet_utxos = wollet.utxos().map_err(|e| {
            format!("phone-local Liquid UTXO selection failed: {e}")
        })?;
        let wallet_debug = wallet_utxos
            .iter()
            .map(|utxo| {
                format!(
                    "{}:{}:{}:{}",
                    utxo.outpoint.txid,
                    utxo.outpoint.vout,
                    utxo.unblinded.asset,
                    utxo.unblinded.value
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let wallet_outpoints =
            wallet_utxos.into_iter().map(|utxo| utxo.outpoint).collect();
        let explicit_utxos = wollet.explicit_utxos().map_err(|e| {
            format!("phone-local Liquid explicit UTXO selection failed: {e}")
        })?;
        let explicit_debug = explicit_utxos
            .iter()
            .map(|utxo| {
                format!(
                    "{}:{}:{}:{}",
                    utxo.outpoint.txid,
                    utxo.outpoint.vout,
                    utxo.unblinded.asset,
                    utxo.unblinded.value
                )
            })
            .collect::<Vec<_>>()
            .join(",");
        let mut builder = wollet
            .tx_builder()
            .fee_rate(Some(1000.0))
            .set_wallet_utxos(wallet_outpoints);
        if !explicit_utxos.is_empty() {
            builder =
                builder.add_external_utxos(explicit_utxos).map_err(|e| {
                    format!("phone-local Liquid explicit UTXO add failed: {e}")
                })?;
        }
        let mut pset = builder
            .add_unvalidated_recipient(&recipient)
            .map_err(|e| format!("phone-local Liquid recipient failed: {e}"))?
            .finish()
            .map_err(|e| format!("phone-local Liquid transaction build failed: {e}; wallet_utxos=[{wallet_debug}]; explicit_utxos=[{explicit_debug}]"))?;
        let signer = self.lwk_signer()?;
        let sigs = signer
            .sign(&mut pset)
            .map_err(|e| format!("phone-local Liquid signing failed: {e}"))?;
        if sigs == 0 {
            return Err(
                "phone-local Liquid signing produced no signatures".into()
            );
        }
        let tx = wollet
            .finalize(&mut pset)
            .map_err(|e| format!("phone-local Liquid finalize failed: {e}"))?;
        let txid = self
            .lwk_electrum_client()?
            .broadcast(&tx)
            .map_err(|e| format!("Liquid Electrum broadcast failed: {e}"))?;
        Ok(json!({
            "txid": txid.to_string(),
            "mode": "phone-local-electrum",
            "submitted": true
        })
        .to_string())
    }

    pub(crate) fn demo_pedersen_rangeproof(&self, value: u64) -> Value {
        json!({
            "pedersen_commitment": "demo_only",
            "rangeproof_len": 512,
            "verified": true,
            "value_demo": value,
            "next_index_at_demo": self.next_index,
            "warning": "DEMO ONLY - NOT A REAL INTEGRATED CONFIDENTIAL TX / RANGEPROOF. See transfer_json + design §273."
        })
    }
}

fn liquid_quic_remote(quic_url: &str) -> Result<SocketAddr, String> {
    quic_url
        .to_socket_addrs()
        .map_err(|err| format!("invalid Liquid QUIC peer {quic_url}: {err}"))?
        .next()
        .ok_or_else(|| format!("Liquid QUIC peer {quic_url} did not resolve"))
}

fn liquid_quic_update_from_message(
    line: &[u8],
) -> Result<LiteWalletUpdate, String> {
    let message: Value =
        serde_json::from_slice(line).map_err(|e| e.to_string())?;
    let message_type = message
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| "QUIC message missing type".to_string())?;
    if message_type == "error" {
        let message = message
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("liquid-simplicity lite-wallet error");
        return Err(message.to_string());
    }
    match message_type {
        "snapshot" | "confirmed" | "mempool" => {
            let update_val = message.get("update").ok_or_else(|| {
                format!("{message_type} message missing update")
            })?;
            let update: LiteWalletUpdate =
                serde_json::from_value(update_val.clone())
                    .map_err(|e| format!("failed to decode update: {e}"))?;
            Ok(update)
        }
        other => Err(format!("unknown QUIC message type {other}")),
    }
}

fn liquid_quic_endpoint(remote: SocketAddr) -> Result<quinn::Endpoint, String> {
    let bind_addr: SocketAddr = if remote.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    }
    .parse()
    .map_err(|err| format!("invalid QUIC bind address: {err}"))?;
    let mut endpoint = quinn::Endpoint::client(bind_addr)
        .map_err(|err| format!("could not create QUIC endpoint: {err}"))?;
    endpoint.set_default_client_config(liquid_quic_client_config()?);
    Ok(endpoint)
}

fn liquid_quic_client_config() -> Result<quinn::ClientConfig, String> {
    #[derive(Debug)]
    struct SkipServerVerification;

    impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer,
            _intermediates: &[rustls::pki_types::CertificateDer],
            _server_name: &rustls::pki_types::ServerName,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<
            rustls::client::danger::HandshakeSignatureValid,
            rustls::Error,
        > {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &rustls::pki_types::CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<
            rustls::client::danger::HandshakeSignatureValid,
            rustls::Error,
        > {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    crypto.alpn_protocols = vec![LIQUID_QUIC_ALPN.to_vec()];
    let client_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto).map_err(
            |err| format!("could not create QUIC rustls client config: {err}"),
        )?;
    Ok(quinn::ClientConfig::new(Arc::new(client_config)))
}

fn atomic_write(path: &std::path::Path, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, contents).map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

fn get_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("failed to build tokio runtime for FFI wallet")
    })
}

fn local_sidechain_address_params() -> &'static AddressParams {
    static LOCAL_SIDECHAIN_PARAMS: std::sync::LazyLock<AddressParams> =
        std::sync::LazyLock::new(|| AddressParams {
            p2pkh_prefix: 111,
            p2sh_prefix: 196,
            blinded_prefix: 4,
            bech_hrp: Hrp::parse_unchecked("bcrt"),
            blech_hrp: Hrp::parse_unchecked("bcrt"),
        });
    &LOCAL_SIDECHAIN_PARAMS
}

fn derive_next_confidential_address(
    index: u32,
    master: &Xpriv,
) -> Result<String, String> {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    let spend_dp = DerivationPath::master()
        .child(ChildNumber::Hardened { index: 84 })
        .child(ChildNumber::Hardened { index: 1 })
        .child(ChildNumber::Hardened { index: 0 })
        .child(ChildNumber::Normal { index: 0 })
        .child(ChildNumber::Normal { index });
    let spend_xpriv = master
        .derive_priv(&secp, &spend_dp)
        .map_err(|e| e.to_string())?;
    let spend_pk: bitcoin::PublicKey =
        spend_xpriv.private_key.public_key(&secp).into();

    let blind_dp = DerivationPath::master()
        .child(ChildNumber::Hardened { index: 84 })
        .child(ChildNumber::Hardened { index: 1 })
        .child(ChildNumber::Hardened { index: 0 })
        .child(ChildNumber::Normal { index: 1 })
        .child(ChildNumber::Normal { index });
    let blind_xpriv = master
        .derive_priv(&secp, &blind_dp)
        .map_err(|e| e.to_string())?;
    let blind_secp_pk: bitcoin::secp256k1::PublicKey =
        blind_xpriv.private_key.public_key(&secp);
    let blind_elements_pk = elements::secp256k1_zkp::PublicKey::from_slice(
        &blind_secp_pk.serialize(),
    )
    .map_err(|e| e.to_string())?;

    let base = ElementsAddress::p2wpkh(
        &spend_pk,
        None,
        local_sidechain_address_params(),
    );

    Ok(base.to_confidential(blind_elements_pk).to_string())
}
