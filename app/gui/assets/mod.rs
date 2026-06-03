use eframe::egui;
use strum::{EnumIter, IntoEnumIterator};

use crate::app::App;

mod all_assets;
mod reserve_register;

use all_assets::AllAssets;
use reserve_register::ReserveRegister;

#[derive(Default, EnumIter, Eq, PartialEq, strum::Display)]
enum Tab {
    #[default]
    #[strum(to_string = "All Assets")]
    AllAssets,
    #[strum(to_string = "Reserve & Register")]
    ReserveRegister,
}

#[derive(Default)]
pub struct Assets {
    all_assets: AllAssets,
    reserve_register: ReserveRegister,
    tab: Tab,
}

impl Assets {
    pub fn show(&mut self, app: Option<&App>, ui: &mut egui::Ui) {
        egui::TopBottomPanel::top("assets_tabs").show(ui.ctx(), |ui| {
            ui.horizontal(|ui| {
                Tab::iter().for_each(|tab_variant| {
                    let tab_name = tab_variant.to_string();
                    ui.selectable_value(&mut self.tab, tab_variant, tab_name);
                })
            });
        });
        egui::CentralPanel::default().show(ui.ctx(), |ui| match self.tab {
            Tab::AllAssets => {
                let () = self.all_assets.show(app, ui);
            }
            Tab::ReserveRegister => {
                let () = self.reserve_register.show(app, ui);
            }
        });
    }
}
