use crossterm::event::{KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::core::errors::PinGuardError;
use crate::tui::theme::Theme;
use super::{Screen, AsyncKeyHandler, ScreenAction};

pub struct FixerScreen {
    placeholder: String,
}

impl FixerScreen {
    pub fn new() -> Self {
        Self {
            placeholder: "Fixer screen - coming soon".to_string(),
        }
    }
}

impl Screen for FixerScreen {
    fn title(&self) -> &str {
        "Security Fixer"
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let content = Paragraph::new("🛠️ Güvenlik Düzeltme Aracı\n\nBu özellik yakında geliyor...")
            .block(
                Block::default()
                    .title(" 🛠️ Security Fixer ")
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
impl AsyncKeyHandler for FixerScreen {
    async fn handle_key_events(&mut self, _key_event: KeyEvent) 
        -> Result<Option<ScreenAction>, PinGuardError> {
        Ok(None)
    }
}