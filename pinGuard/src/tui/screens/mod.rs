use crossterm::event::KeyEvent;
use ratatui::prelude::*;

use crate::core::errors::PinGuardError;
use crate::tui::theme::Theme;

pub mod main_menu;
pub mod scanner;
pub mod fixer;
pub mod reports;
pub mod settings;

pub use main_menu::MainMenuScreen;
pub use scanner::ScannerScreen;
pub use fixer::FixerScreen;
pub use reports::ReportsScreen;
pub use settings::SettingsScreen;

/// Ekran türleri
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScreenType {
    MainMenu,
    Scanner,
    Fixer,
    Reports,
    Settings,
}

/// Ekran action'ları
#[derive(Debug, Clone)]
pub enum ScreenAction {
    SwitchScreen(ScreenType),
    Quit,
    SetStatus(String),
    SetLoading(bool),
    GoBack,
}

/// Screen trait - tüm ekranların implement etmesi gereken trait
/// Not: async fonksiyonları dyn compatible olmak için ayrı tutuyoruz
pub trait Screen {
    /// Ekranı render et
    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme);
    
    /// Tick event'ini handle et (animasyonlar, progress updates vs.)
    fn tick(&mut self) {}
    
    /// Ekran initialize olduğunda çağrılır
    fn on_enter(&mut self) {}
    
    /// Ekrandan çıkarken çağrılır
    fn on_exit(&mut self) {}
    
    /// Terminal resize olduğunda çağrılır
    fn on_resize(&mut self, _width: u16, _height: u16) {}
    
    /// Ekranın title'ını döndür
    fn title(&self) -> &str;
    
    /// Ekranın help text'ini döndür
    fn help_text(&self) -> Vec<(&str, &str)> {
        vec![("ESC", "Back"), ("Ctrl+C", "Quit")]
    }
}

/// Async key handler trait
#[async_trait::async_trait]
pub trait AsyncKeyHandler {
    /// Klavye input'unu handle et
    async fn handle_key_events(&mut self, key_event: KeyEvent) 
        -> Result<Option<ScreenAction>, PinGuardError>;
}