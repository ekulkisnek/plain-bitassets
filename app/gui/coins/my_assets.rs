use eframe::egui;
use itertools::{Either, Itertools};

use liquid_simplicity::types::{BitAssetId, FilledOutput, Hash, Txid};

use crate::{app::App, gui::util::UiExt};

type KnownNameReservation = (Txid, Hash, String);
type UnknownNameReservation = (Txid, Hash);

#[derive(Debug, Default)]
pub struct MyAssets;

impl MyAssets {
    /// Returns asset reservations with known and unknown names
    fn get_asset_reservations(
        app: &App,
    ) -> (Vec<KnownNameReservation>, Vec<UnknownNameReservation>) {
        let utxos_read = app.utxos.read();
        // all asset reservations
        let bitasset_reservations = utxos_read
            .values()
            .filter_map(FilledOutput::reservation_data);
        // split into asset reservations for which the names are known,
        // or unknown
        let (
            mut known_name_bitasset_reservations,
            mut unknown_name_bitasset_reservations,
        ): (Vec<_>, Vec<_>) =
            bitasset_reservations.partition_map(|(txid, commitment)| {
                let plain_bitasset = app
                    .wallet
                    .get_bitasset_reservation_plaintext(commitment)
                    .expect("failed to retrieve asset reservation data");
                match plain_bitasset {
                    Some(plain_bitasset) => {
                        Either::Left((*txid, *commitment, plain_bitasset))
                    }
                    None => Either::Right((*txid, *commitment)),
                }
            });
        // sort name-known asset reservations by plain name
        known_name_bitasset_reservations.sort_by(
            |(_, _, plain_name_l), (_, _, plain_name_r)| {
                plain_name_l.cmp(plain_name_r)
            },
        );
        // sort name-unknown asset reservations by txid
        unknown_name_bitasset_reservations.sort_by_key(|(txid, _)| *txid);
        (
            known_name_bitasset_reservations,
            unknown_name_bitasset_reservations,
        )
    }

    pub fn show_reservations(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        let (
            known_name_bitasset_reservations,
            unknown_name_bitasset_reservations,
        ) = app.map(Self::get_asset_reservations).unwrap_or_default();
        let _response = egui::SidePanel::left("My Asset Reservations")
            .exact_width(350.)
            .resizable(false)
            .show_inside(ui, move |ui| {
                ui.heading("Asset Reservations");
                egui::Grid::new("My Asset Reservations")
                    .num_columns(1)
                    .striped(true)
                    .show(ui, |ui| {
                        for (txid, commitment, plaintext_name) in
                            known_name_bitasset_reservations
                        {
                            let txid = hex::encode(txid.0);
                            let commitment = hex::encode(commitment);
                            ui.vertical(|ui| {
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!("plaintext name: {plaintext_name}"),
                                );
                                ui.monospace_selectable_singleline(
                                    false,
                                    format!("txid: {txid}"),
                                );
                                ui.monospace_selectable_singleline(
                                    false,
                                    format!("commitment: {commitment}"),
                                );
                            });
                            ui.end_row()
                        }
                        for (txid, commitment) in
                            unknown_name_bitasset_reservations
                        {
                            let txid = hex::encode(txid.0);
                            let commitment = hex::encode(commitment);
                            ui.vertical(|ui| {
                                ui.monospace_selectable_singleline(
                                    false,
                                    format!("txid: {txid}"),
                                );
                                ui.monospace_selectable_singleline(
                                    false,
                                    format!("commitment: {commitment}"),
                                );
                            });
                            ui.end_row()
                        }
                    });
            });
    }

    /// Returns Assets with known and unknown names
    fn get_assets(app: &App) -> (Vec<(BitAssetId, String)>, Vec<BitAssetId>) {
        let utxos_read = app.utxos.read();
        // all owned assets
        let bitassets = utxos_read.values().filter_map(FilledOutput::bitasset);
        // split into assets for which the names are known or unknown
        let (mut known_name_bitassets, mut unknown_name_bitassets): (
            Vec<_>,
            Vec<_>,
        ) = bitassets.partition_map(|bitasset| {
            let plain_bitasset = app
                .wallet
                .get_bitasset_plaintext(bitasset)
                .expect("failed to retrieve asset data");
            match plain_bitasset {
                Some(plain_bitasset) => {
                    Either::Left((*bitasset, plain_bitasset))
                }
                None => Either::Right(*bitasset),
            }
        });
        // sort name-known assets by plain name
        known_name_bitassets.sort_by(|(_, plain_name_l), (_, plain_name_r)| {
            plain_name_l.cmp(plain_name_r)
        });
        // sort name-unknown assets by asset value
        unknown_name_bitassets.sort();
        (known_name_bitassets, unknown_name_bitassets)
    }

    pub fn show_assets(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        let (known_name_bitassets, unknown_name_bitassets) =
            app.map(Self::get_assets).unwrap_or_default();
        let balances = app
            .map(|app| {
                let utxos_read = app.utxos.read();
                let mut balances =
                    std::collections::HashMap::<BitAssetId, u64>::new();
                for output in utxos_read.values() {
                    if let Some((
                        liquid_simplicity::types::AssetId::BitAsset(
                            bitasset_id,
                        ),
                        value,
                    )) = output.asset_value()
                    {
                        *balances.entry(bitasset_id).or_default() += value;
                    }
                }
                balances
            })
            .unwrap_or_default();

        egui::SidePanel::left("My Assets")
            .exact_width(350.)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.heading("Assets");
                egui::Grid::new("My Assets")
                    .striped(true)
                    .num_columns(1)
                    .show(ui, |ui| {
                        for (bitasset, plaintext_name) in known_name_bitassets {
                            let balance =
                                balances.get(&bitasset).copied().unwrap_or(0);
                            ui.vertical(|ui| {
                                ui.monospace_selectable_singleline(
                                    true,
                                    format!("plaintext name: {plaintext_name}"),
                                );
                                ui.monospace_selectable_singleline(
                                    false,
                                    format!(
                                        "Asset ID: {}",
                                        hex::encode(bitasset.0)
                                    ),
                                );
                                ui.monospace_selectable_singleline(
                                    false,
                                    format!("Balance: {balance} units"),
                                );
                            });
                            ui.end_row()
                        }
                        for bitasset in unknown_name_bitassets {
                            let balance =
                                balances.get(&bitasset).copied().unwrap_or(0);
                            ui.vertical(|ui| {
                                ui.monospace_selectable_singleline(
                                    false,
                                    format!(
                                        "Asset ID: {}",
                                        hex::encode(bitasset.0)
                                    ),
                                );
                                ui.monospace_selectable_singleline(
                                    false,
                                    format!("Balance: {balance} units"),
                                );
                            });
                            ui.end_row()
                        }
                    });
            });
    }

    pub fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        let _reservations_response = self.show_reservations(app, ui);
        let _bitassets_response = self.show_assets(app, ui);
    }
}
