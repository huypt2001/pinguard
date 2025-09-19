use crossterm::event::{KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::core::errors::PinGuardError;
use crate::tui::theme::Theme;
use super::{Screen, AsyncKeyHandler, ScreenAction};

pub struct ReportsScreen {
    placeholder: String,
}

impl ReportsScreen {
    pub fn new() -> Self {
        Self {
            placeholder: "Reports screen - coming soon".to_string(),
        }
    }
}

impl Screen for ReportsScreen {
    fn title(&self) -> &str {
        "Security Reports"
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let content = Paragraph::new("📊 Güvenlik Raporları\n\nBu özellik yakında geliyor...")
            .block(
                Block::default()
                    .title(" 📊 Security Reports ")
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
impl AsyncKeyHandler for ReportsScreen {
    async fn handle_key_events(&mut self, _key_event: KeyEvent) 
        -> Result<Option<ScreenAction>, PinGuardError> {
        Ok(None)
    }
}