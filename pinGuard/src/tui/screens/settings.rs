use crossterm::event::{KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::core::errors::PinGuardError;
use crate::tui::theme::Theme;
use super::{Screen, AsyncKeyHandler, ScreenAction};

pub struct SettingsScreen {
    placeholder: String,
}

impl SettingsScreen {
    pub fn new() -> Self {
        Self {
            placeholder: "Settings screen - coming soon".to_string(),
        }
    }
}

impl Screen for SettingsScreen {
    fn title(&self) -> &str {
        "Settings"
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let content = Paragraph::new("⚙️ Ayarlar\n\nBu özellik yakında geliyor...")
            .block(
                Block::default()
                    .title(" ⚙️ Settings ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .alignment(Alignment::Center)
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(content, area);
    }
}

#[async_trait::async_trait]
impl AsyncKeyHandler for SettingsScreen {
    async fn handle_key_events(&mut self, _key_event: KeyEvent) 
        -> Result<Option<ScreenAction>, PinGuardError> {
        Ok(None)
    }
}