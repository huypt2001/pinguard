use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Gauge, Paragraph};

use super::theme::Theme;

/// Progress bar component
pub struct ProgressBar {
    pub progress: f64,
    pub title: String,
    pub show_percentage: bool,
}

impl ProgressBar {
    pub fn new(title: String) -> Self {
        Self {
            progress: 0.0,
            title,
            show_percentage: true,
        }
    }

    pub fn set_progress(&mut self, progress: f64) {
        self.progress = progress.clamp(0.0, 1.0);
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let gauge = Gauge::default()
            .block(
                Block::default()
                    .title(self.title.as_str())
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .gauge_style(theme.progress_style())
            .percent((self.progress * 100.0) as u16)
            .label(if self.show_percentage {
                format!("{:.1}%", self.progress * 100.0)
            } else {
                String::new()
            });

        frame.render_widget(gauge, area);
    }
}

/// Status indicator component
pub struct StatusIndicator {
    pub status: String,
    pub message: String,
}

impl StatusIndicator {
    pub fn new(status: String, message: String) -> Self {
        Self { status, message }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let style = match self.status.to_lowercase().as_str() {
            "success" | "ok" => theme.success_style(),
            "warning" | "warn" => theme.warning_style(),
            "error" | "fail" => theme.error_style(),
            "critical" => theme.critical_style(),
            _ => theme.info_style(),
        };

        let symbol = match self.status.to_lowercase().as_str() {
            "success" | "ok" => "✓",
            "warning" | "warn" => "⚠",
            "error" | "fail" => "✗",
            "critical" => "🔥",
            "info" => "ⓘ",
            _ => "•",
        };

        let content = Paragraph::new(format!("{} {}", symbol, self.message))
            .style(style)
            .alignment(Alignment::Left)
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(content, area);
    }
}

/// Help text component
pub struct HelpText {
    pub items: Vec<(String, String)>,
}

impl HelpText {
    pub fn new(items: Vec<(&str, &str)>) -> Self {
        Self {
            items: items.into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    pub fn render(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let lines: Vec<Line> = self.items
            .iter()
            .map(|(key, desc)| {
                Line::from(vec![
                    Span::styled(key, theme.accent_style()),
                    Span::styled(": ", theme.muted_style()),
                    Span::styled(desc, theme.list_item_style()),
                ])
            })
            .collect();

        let help = Paragraph::new(lines)
            .block(
                Block::default()
                    .title(" 📋 Yardım ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(help, area);
    }
}