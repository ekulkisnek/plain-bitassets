use eframe::egui::{self, Button};
use liquid_simplicity::types::{Address, AssetId};

use super::utxo_selector::AssetInput;
use crate::{app::App, gui::util::UiExt};

#[derive(Debug, Default)]
struct Transfer {
    dest: String,
    asset_input: AssetInput,
    amount: String,
    fee: String,
}

fn create_transfer(
    app: &App,
    dest: Address,
    asset_id: AssetId,
    amount: u64,
    fee: bitcoin::Amount,
) -> anyhow::Result<()> {
    let tx = match asset_id {
        AssetId::Bitcoin => app.wallet.create_transfer(
            dest,
            bitcoin::Amount::from_sat(amount),
            fee,
            None,
        )?,
        AssetId::BitAsset(bitasset_id) => app.wallet.create_bitasset_transfer(
            dest,
            bitasset_id,
            amount,
            fee,
            None,
        )?,
        AssetId::BitAssetControl(_) => {
            return Err(anyhow::anyhow!(
                "Cannot transfer a control coin directly."
            ));
        }
    };
    app.sign_and_send(tx)?;
    Ok(())
}

impl Transfer {
    fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        ui.add_sized((250., 10.), |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                let dest_edit = egui::TextEdit::singleline(&mut self.dest)
                    .hint_text("destination address")
                    .desired_width(150.);
                ui.add(dest_edit);
            })
            .response
        });
        ui.horizontal(|ui| {
            ui.monospace("Asset:       ");
            self.asset_input.show(ui);
        });
        let asset_id_res = self.asset_input.asset_id();
        ui.add_sized((110., 10.), |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                let amount_edit = egui::TextEdit::singleline(&mut self.amount)
                    .hint_text("amount")
                    .desired_width(80.);
                ui.add(amount_edit);
                if let Ok(AssetId::Bitcoin) = asset_id_res {
                    ui.label("BTC");
                } else {
                    ui.label("units");
                }
            })
            .response
        });
        ui.add_sized((110., 10.), |ui: &mut egui::Ui| {
            ui.horizontal(|ui| {
                let fee_edit = egui::TextEdit::singleline(&mut self.fee)
                    .hint_text("fee")
                    .desired_width(80.);
                ui.add(fee_edit);
                ui.label("BTC");
            })
            .response
        });
        let dest: Option<Address> = self.dest.parse().ok();
        let fee = bitcoin::Amount::from_str_in(
            &self.fee,
            bitcoin::Denomination::Bitcoin,
        );
        let amount_sats_or_units = if let Ok(AssetId::Bitcoin) = asset_id_res {
            bitcoin::Amount::from_str_in(
                &self.amount,
                bitcoin::Denomination::Bitcoin,
            )
            .ok()
            .map(|amt| amt.to_sat())
        } else {
            self.amount.parse::<u64>().ok()
        };
        if ui
            .add_enabled(
                app.is_some()
                    && dest.is_some()
                    && asset_id_res.is_ok()
                    && amount_sats_or_units.is_some()
                    && fee.is_ok(),
                egui::Button::new("transfer"),
            )
            .clicked()
        {
            let asset_id = asset_id_res.unwrap();
            let amount = amount_sats_or_units.unwrap();
            if let Err(err) = create_transfer(
                app.unwrap(),
                dest.expect("should not happen"),
                asset_id,
                amount,
                fee.expect("should not happen"),
            ) {
                tracing::error!("{err:#}");
            } else {
                *self = Self::default();
            }
        }
    }
}

#[derive(Debug)]
struct Receive {
    address: Option<anyhow::Result<Address>>,
}

impl Receive {
    fn new(app: Option<&App>) -> Self {
        let Some(app) = app else {
            return Self { address: None };
        };
        let address = app
            .wallet
            .get_new_address()
            .map_err(anyhow::Error::from)
            .inspect_err(|err| tracing::error!("{err:#}"));
        Self {
            address: Some(address),
        }
    }

    fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        match &self.address {
            Some(Ok(address)) => {
                ui.monospace_selectable_singleline(false, address.to_string());
            }
            Some(Err(err)) => {
                ui.monospace_selectable_multiline(format!("{err:#}"));
            }
            None => (),
        }
        if ui
            .add_enabled(app.is_some(), Button::new("generate"))
            .clicked()
        {
            *self = Self::new(app)
        }
    }
}

#[derive(Debug)]
pub(super) struct TransferReceive {
    transfer: Transfer,
    receive: Receive,
}

impl TransferReceive {
    pub fn new(app: Option<&App>) -> Self {
        Self {
            transfer: Transfer::default(),
            receive: Receive::new(app),
        }
    }

    pub fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        egui::SidePanel::left("transfer")
            .exact_width(ui.available_width() / 2.)
            .resizable(false)
            .show_inside(ui, |ui| {
                ui.vertical_centered(|ui| {
                    ui.heading("Transfer");
                    self.transfer.show(app, ui);
                })
            });
        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Receive");
                self.receive.show(app, ui);
            })
        });
    }
}
