use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::prelude::*;

use crate::core::errors::PinGuardError;
use super::theme::Theme;
use super::screens::{ScreenType, ScreenAction, MainMenuScreen, ScannerScreen, FixerScreen, ReportsScreen, SettingsScreen, Screen, AsyncKeyHandler};

pub type AppResult<T> = Result<T, PinGuardError>;

/// Tüm screen'leri içeren enum
pub enum AppScreen {
    MainMenu(MainMenuScreen),
    Scanner(ScannerScreen),
    Fixer(FixerScreen),
    Reports(ReportsScreen),
    Settings(SettingsScreen),
}

impl AppScreen {
    fn get_screen_mut(&mut self) -> &mut dyn Screen {
        match self {
            AppScreen::MainMenu(s) => s,
            AppScreen::Scanner(s) => s,
            AppScreen::Fixer(s) => s,
            AppScreen::Reports(s) => s,
            AppScreen::Settings(s) => s,
        }
    }

    async fn handle_key_events(&mut self, key_event: KeyEvent) -> Result<Option<ScreenAction>, PinGuardError> {
        match self {
            AppScreen::MainMenu(s) => AsyncKeyHandler::handle_key_events(s, key_event).await,
            AppScreen::Scanner(s) => AsyncKeyHandler::handle_key_events(s, key_event).await,
            AppScreen::Fixer(s) => AsyncKeyHandler::handle_key_events(s, key_event).await,
            AppScreen::Reports(s) => AsyncKeyHandler::handle_key_events(s, key_event).await,
            AppScreen::Settings(s) => AsyncKeyHandler::handle_key_events(s, key_event).await,
        }
    }
}

/// Ana uygulama state'i
pub struct App {
    /// Çıkış flag'i
    pub should_quit: bool,
    /// Mevcut ekran
    pub current_screen: ScreenType,
    /// Tema
    pub theme: Theme,
    /// Ekranlar
    pub screens: HashMap<ScreenType, AppScreen>,
    /// Terminal boyutu
    pub terminal_size: (u16, u16),
    /// Genel durum mesajı
    pub status_message: Option<String>,
    /// Loading durumu
    pub is_loading: bool,
}

impl App {
    /// Yeni uygulama instance'ı oluştur
    pub fn new() -> Self {
        let mut screens: HashMap<ScreenType, AppScreen> = HashMap::new();
        
        // Ekranları initialize et
        screens.insert(ScreenType::MainMenu, AppScreen::MainMenu(MainMenuScreen::new()));
        screens.insert(ScreenType::Scanner, AppScreen::Scanner(ScannerScreen::new()));
        screens.insert(ScreenType::Fixer, AppScreen::Fixer(FixerScreen::new()));
        screens.insert(ScreenType::Reports, AppScreen::Reports(ReportsScreen::new()));
        screens.insert(ScreenType::Settings, AppScreen::Settings(SettingsScreen::new()));

        Self {
            should_quit: false,
            current_screen: ScreenType::MainMenu,
            theme: Theme::default(),
            screens,
            terminal_size: (80, 24),
            status_message: None,
            is_loading: false,
        }
    }

    /// Çıkış durumunu kontrol et
    pub fn should_quit(&self) -> bool {
        self.should_quit
    }

    /// Çıkış flag'ini set et
    pub fn quit(&mut self) {
        self.should_quit = true;
    }

    /// Ekran değiştir
    pub fn switch_screen(&mut self, screen_type: ScreenType) {
        if self.screens.contains_key(&screen_type) {
            self.current_screen = screen_type;
        }
    }

    /// Ana geri dön
    pub fn go_back(&mut self) {
        match self.current_screen {
            ScreenType::MainMenu => self.quit(),
            _ => self.switch_screen(ScreenType::MainMenu),
        }
    }

    /// Terminal resize handle et
    pub fn handle_resize(&mut self, width: u16, height: u16) {
        self.terminal_size = (width, height);
        // Ekranlara resize bilgisini ilet
        for screen in self.screens.values_mut() {
            screen.get_screen_mut().on_resize(width, height);
        }
    }

    /// Durum mesajı set et
    pub fn set_status(&mut self, message: String) {
        self.status_message = Some(message);
    }

    /// Durum mesajını temizle
    pub fn clear_status(&mut self) {
        self.status_message = None;
    }

    /// Loading durumunu set et
    pub fn set_loading(&mut self, loading: bool) {
        self.is_loading = loading;
    }

    /// Tick event'i handle et
    pub fn tick(&mut self) {
        // Mevcut ekranın tick fonksiyonunu çağır
        if let Some(screen) = self.screens.get_mut(&self.current_screen) {
            screen.get_screen_mut().tick();
        }
    }

    /// Klavye event'lerini handle et
    pub async fn handle_key_events(&mut self, key_event: KeyEvent) -> AppResult<()> {
        // Global kısayollar
        match key_event.code {
            KeyCode::Char('c') if key_event.modifiers.contains(KeyModifiers::CONTROL) => {
                self.quit();
                return Ok(());
            }
            KeyCode::Esc => {
                self.go_back();
                return Ok(());
            }
            KeyCode::F(1) => {
                self.switch_screen(ScreenType::MainMenu);
                return Ok(());
            }
            KeyCode::F(2) => {
                self.switch_screen(ScreenType::Scanner);
                return Ok(());
            }
            KeyCode::F(3) => {
                self.switch_screen(ScreenType::Fixer);
                return Ok(());
            }
            KeyCode::F(4) => {
                self.switch_screen(ScreenType::Reports);
                return Ok(());
            }
            KeyCode::F(5) => {
                self.switch_screen(ScreenType::Settings);
                return Ok(());
            }
            _ => {}
        }

        // Mevcut ekranın key handler'ını çağır
        if let Some(screen) = self.screens.get_mut(&self.current_screen) {
            if let Some(action) = screen.handle_key_events(key_event).await? {
                self.handle_screen_action(action).await?;
            }
        }

        Ok(())
    }

    /// Ekran action'larını handle et
    async fn handle_screen_action(&mut self, action: ScreenAction) -> AppResult<()> {
        match action {
            ScreenAction::SwitchScreen(screen_type) => {
                self.switch_screen(screen_type);
            }
            ScreenAction::Quit => {
                self.quit();
            }
            ScreenAction::SetStatus(message) => {
                self.set_status(message);
            }
            ScreenAction::SetLoading(loading) => {
                self.set_loading(loading);
            }
            ScreenAction::GoBack => {
                self.go_back();
            }
        }

        Ok(())
    }

    /// UI'yi render et
    pub fn render(&mut self, frame: &mut Frame) {
        // Ana layout
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Content
                Constraint::Length(3), // Footer/Status
            ])
            .split(frame.size());

        // Header çiz
        self.render_header(frame, layout[0]);

        // Mevcut ekranı çiz
        if let Some(screen) = self.screens.get_mut(&self.current_screen) {
            screen.get_screen_mut().render(frame, layout[1], &self.theme);
        }

        // Footer çiz
        self.render_footer(frame, layout[2]);
    }

    /// Header'ı render et
    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let title = match self.current_screen {
            ScreenType::MainMenu => "🛡️  PinGuard - Linux Security Scanner",
            ScreenType::Scanner => "🔍 Security Scanner",
            ScreenType::Fixer => "🛠️  Security Fixer",
            ScreenType::Reports => "📊 Security Reports",
            ScreenType::Settings => "⚙️  Settings",
        };

        let header = ratatui::widgets::Paragraph::new(title)
            .style(self.theme.header_style())
            .alignment(Alignment::Center)
            .wrap(ratatui::widgets::Wrap { trim: true })
            .block(
                ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .border_style(self.theme.border_style())
                    .style(self.theme.box_style()),
            );

        frame.render_widget(header, area);
    }

    /// Footer'ı render et
    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let mut footer_text = vec![
            Line::from(vec![
                Span::styled("F1", self.theme.accent_style()),
                Span::raw(": Menu "),
                Span::styled("F2", self.theme.accent_style()),
                Span::raw(": Scan "),
                Span::styled("F3", self.theme.accent_style()),
                Span::raw(": Fix "),
                Span::styled("F4", self.theme.accent_style()),
                Span::raw(": Reports "),
                Span::styled("F5", self.theme.accent_style()),
                Span::raw(": Settings "),
            ])
        ];

        if let Some(ref status) = self.status_message {
            footer_text.push(Line::from(vec![
                Span::styled("Status: ", self.theme.info_style()),
                Span::styled(status, self.theme.success_style()),
            ]));
        }

        footer_text.push(Line::from(vec![
            Span::styled("ESC", self.theme.accent_style()),
            Span::raw(": Back  "),
            Span::styled("Ctrl+C", self.theme.accent_style()),
            Span::raw(": Quit"),
        ]));

        let footer = ratatui::widgets::Paragraph::new(footer_text)
            .style(self.theme.muted_style())
            .alignment(Alignment::Left)
            .wrap(ratatui::widgets::Wrap { trim: true })
            .block(
                ratatui::widgets::Block::default()
                    .borders(ratatui::widgets::Borders::ALL)
                    .border_style(self.theme.border_style())
                    .style(self.theme.box_style()),
            );

        frame.render_widget(footer, area);
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}

// Theme için accent_style eklememiz gerekiyor
impl Theme {
    pub fn accent_style(&self) -> Style {
        Style::default().fg(self.accent).add_modifier(Modifier::BOLD)
    }
}