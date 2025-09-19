use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, List, ListItem, ListState, BarChart, Cell, Row, Table};

use crate::core::errors::PinGuardError;
use crate::scanners::{ScanResult, ScanStatus, Severity};
use crate::tui::theme::Theme;
use super::{Screen, AsyncKeyHandler, ScreenAction, ScreenType};

#[derive(Debug, Clone)]
pub enum ReportView {
    Summary,
    Details,
    Charts,
}

pub struct ReportsScreen {
    scan_results: Vec<ScanResult>,
    current_view: ReportView,
    list_state: ListState,
    selected_result_index: Option<usize>,
}

impl ReportsScreen {
    pub fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));

        Self {
            scan_results: Vec::new(),
            current_view: ReportView::Summary,
            list_state,
            selected_result_index: None,
        }
    }

    /// Scan sonuçlarını yükle
    pub fn load_scan_results(&mut self, results: Vec<ScanResult>) {
        self.scan_results = results;
        if !self.scan_results.is_empty() {
            self.list_state.select(Some(0));
            self.selected_result_index = Some(0);
        }
    }

    fn next_view(&mut self) {
        self.current_view = match self.current_view {
            ReportView::Summary => ReportView::Details,
            ReportView::Details => ReportView::Charts,
            ReportView::Charts => ReportView::Summary,
        };
    }

    fn previous_view(&mut self) {
        self.current_view = match self.current_view {
            ReportView::Summary => ReportView::Charts,
            ReportView::Details => ReportView::Summary,
            ReportView::Charts => ReportView::Details,
        };
    }

    fn next_result(&mut self) {
        if !self.scan_results.is_empty() {
            let i = match self.list_state.selected() {
                Some(i) => {
                    if i >= self.scan_results.len() - 1 {
                        0
                    } else {
                        i + 1
                    }
                }
                None => 0,
            };
            self.list_state.select(Some(i));
            self.selected_result_index = Some(i);
        }
    }

    fn previous_result(&mut self) {
        if !self.scan_results.is_empty() {
            let i = match self.list_state.selected() {
                Some(i) => {
                    if i == 0 {
                        self.scan_results.len() - 1
                    } else {
                        i - 1
                    }
                }
                None => 0,
            };
            self.list_state.select(Some(i));
            self.selected_result_index = Some(i);
        }
    }

    fn get_summary_stats(&self) -> (u32, u32, u32, u32, u32) {
        let mut total_findings = 0;
        let mut critical = 0;
        let mut high = 0;
        let mut medium = 0;
        let mut low = 0;

        for result in &self.scan_results {
            total_findings += result.findings.len() as u32;
            for finding in &result.findings {
                match finding.severity {
                    Severity::Critical => critical += 1,
                    Severity::High => high += 1,
                    Severity::Medium => medium += 1,
                    Severity::Low => low += 1,
                    Severity::Info => {}
                }
            }
        }

        (total_findings, critical, high, medium, low)
    }
}

impl Screen for ReportsScreen {
    fn title(&self) -> &str {
        "Security Reports"
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        if self.scan_results.is_empty() {
            self.render_empty_state(frame, area, theme);
        } else {
            match self.current_view {
                ReportView::Summary => self.render_summary_view(frame, area, theme),
                ReportView::Details => self.render_details_view(frame, area, theme),
                ReportView::Charts => self.render_charts_view(frame, area, theme),
            }
        }
    }

    fn help_text(&self) -> Vec<(&str, &str)> {
        if self.scan_results.is_empty() {
            vec![
                ("S", "Run scan"),
                ("ESC", "Back"),
            ]
        } else {
            vec![
                ("Tab", "Switch view"),
                ("↑/↓", "Navigate"),
                ("S", "Scanner"),
                ("F", "Fixer"),
                ("ESC", "Back"),
            ]
        }
    }
}

impl ReportsScreen {
    fn render_empty_state(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let content = vec![
            Line::from("📊 Güvenlik Raporları"),
            Line::from(""),
            Line::from("Henüz tarama raporu bulunmuyor."),
            Line::from(""),
            Line::from("Rapor oluşturmak için:"),
            Line::from("• F2 tuşuna basarak Scanner'a gidin"),
            Line::from("• Bir güvenlik taraması çalıştırın"),
            Line::from("• Sonuçları görüntülemek için buraya geri dönün"),
            Line::from(""),
            Line::from(vec![
                Span::styled("S", theme.accent_style()),
                Span::styled(": Scanner'a git", theme.list_item_style()),
            ]),
        ];

        let paragraph = Paragraph::new(content)
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

        frame.render_widget(paragraph, area);
    }

    fn render_summary_view(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),  // Özet istatistikler
                Constraint::Min(0),     // Scanner sonuçları listesi
            ])
            .split(area);

        // Özet istatistikler
        self.render_summary_stats(frame, layout[0], theme);

        // Scanner sonuçları
        self.render_scanner_results_list(frame, layout[1], theme);
    }

    fn render_summary_stats(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let (total, critical, high, medium, low) = self.get_summary_stats();

        let stats_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
                Constraint::Percentage(20),
            ])
            .split(area);

        // Toplam bulgular
        let total_box = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("📊", theme.info_style()),
            ]),
            Line::from(vec![
                Span::styled(total.to_string(), theme.list_item_style().add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Toplam", theme.muted_style()),
            ]),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.border_style())
                .style(theme.box_style())
        )
        .alignment(Alignment::Center);
        frame.render_widget(total_box, stats_layout[0]);

        // Kritik
        let critical_box = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("🔴", theme.critical_style()),
            ]),
            Line::from(vec![
                Span::styled(critical.to_string(), theme.critical_style().add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Kritik", theme.muted_style()),
            ]),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.border_style())
                .style(theme.box_style())
        )
        .alignment(Alignment::Center);
        frame.render_widget(critical_box, stats_layout[1]);

        // Yüksek
        let high_box = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("🟠", theme.error_style()),
            ]),
            Line::from(vec![
                Span::styled(high.to_string(), theme.error_style().add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Yüksek", theme.muted_style()),
            ]),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.border_style())
                .style(theme.box_style())
        )
        .alignment(Alignment::Center);
        frame.render_widget(high_box, stats_layout[2]);

        // Orta
        let medium_box = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("🟡", theme.warning_style()),
            ]),
            Line::from(vec![
                Span::styled(medium.to_string(), theme.warning_style().add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Orta", theme.muted_style()),
            ]),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.border_style())
                .style(theme.box_style())
        )
        .alignment(Alignment::Center);
        frame.render_widget(medium_box, stats_layout[3]);

        // Düşük
        let low_box = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("🟢", theme.success_style()),
            ]),
            Line::from(vec![
                Span::styled(low.to_string(), theme.success_style().add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Düşük", theme.muted_style()),
            ]),
        ])
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(theme.border_style())
                .style(theme.box_style())
        )
        .alignment(Alignment::Center);
        frame.render_widget(low_box, stats_layout[4]);
    }

    fn render_scanner_results_list(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let items: Vec<ListItem> = self
            .scan_results
            .iter()
            .enumerate()
            .map(|(i, result)| {
                let style = if Some(i) == self.list_state.selected() {
                    theme.selected_item_style()
                } else {
                    theme.list_item_style()
                };

                let status_symbol = match result.status {
                    ScanStatus::Success => "✅",
                    ScanStatus::Warning => "⚠️",
                    ScanStatus::Error(_) => "❌",
                    ScanStatus::Skipped(_) => "⏭️",
                };

                let findings_count = result.findings.len();
                let critical_count = result.get_critical_findings().len();
                let high_count = result.get_high_findings().len();

                let content = vec![
                    Line::from(vec![
                        Span::styled(format!(" {} ", status_symbol), theme.accent_style()),
                        Span::styled(&result.scanner_name, style),
                        Span::styled(format!(" ({} bulgular)", findings_count), theme.muted_style()),
                    ]),
                    Line::from(vec![
                        Span::styled("   ", style),
                        Span::styled(format!("Kritik: {} | Yüksek: {}", critical_count, high_count), 
                                    if critical_count > 0 { theme.critical_style() } 
                                    else if high_count > 0 { theme.error_style() } 
                                    else { theme.success_style() }),
                    ]),
                ];

                ListItem::new(content)
            })
            .collect();

        let block = Block::default()
            .title(format!(" � Scanner Sonuçları ({}) ", self.scan_results.len()))
            .title_style(theme.title_style())
            .borders(Borders::ALL)
            .border_style(theme.focused_border_style())
            .style(theme.box_style());

        let list = List::new(items)
            .block(block)
            .highlight_style(theme.selected_item_style());

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_details_view(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        if let Some(index) = self.selected_result_index {
            if let Some(result) = self.scan_results.get(index) {
                let layout = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(6),  // Header info
                        Constraint::Min(0),     // Findings list
                    ])
                    .split(area);

                // Header bilgileri
                self.render_result_header(frame, layout[0], theme, result);

                // Finding'ler listesi
                self.render_findings_list(frame, layout[1], theme, result);
            }
        }
    }

    fn render_result_header(&self, frame: &mut Frame, area: Rect, theme: &Theme, result: &ScanResult) {
        let header_text = vec![
            Line::from(vec![
                Span::styled("�📊 Scanner: ", theme.info_style()),
                Span::styled(&result.scanner_name, theme.list_item_style()),
            ]),
            Line::from(vec![
                Span::styled("🕐 Tarih: ", theme.info_style()),
                Span::styled(&result.scan_time, theme.muted_style()),
            ]),
            Line::from(vec![
                Span::styled("⏱️ Süre: ", theme.info_style()),
                Span::styled(format!("{} ms", result.metadata.duration_ms), theme.muted_style()),
            ]),
            Line::from(vec![
                Span::styled("📋 Bulgular: ", theme.info_style()),
                Span::styled(format!("{}", result.findings.len()), 
                    if result.findings.is_empty() { theme.success_style() } else { theme.warning_style() }),
            ]),
        ];

        let header = Paragraph::new(header_text)
            .block(
                Block::default()
                    .title(" 📊 Tarama Detayları ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            );

        frame.render_widget(header, area);
    }

    fn render_findings_list(&self, frame: &mut Frame, area: Rect, theme: &Theme, result: &ScanResult) {
        if result.findings.is_empty() {
            let empty_message = Paragraph::new("✅ Bu taramada herhangi bir güvenlik sorunu bulunamadı!")
                .block(
                    Block::default()
                        .title(" 🎉 Temiz Tarama ")
                        .title_style(theme.title_style())
                        .borders(Borders::ALL)
                        .border_style(theme.border_style())
                        .style(theme.box_style()),
                )
                .alignment(Alignment::Center)
                .wrap(ratatui::widgets::Wrap { trim: true });

            frame.render_widget(empty_message, area);
            return;
        }

        let rows: Vec<Row> = result.findings
            .iter()
            .map(|finding| {
                let severity_style = theme.severity_style(&format!("{:?}", finding.severity));
                Row::new(vec![
                    Cell::from(format!("{:?}", finding.severity)).style(severity_style),
                    Cell::from(finding.title.clone()),
                    Cell::from(finding.affected_item.clone()),
                    Cell::from(if finding.fix_available { "✅" } else { "❌" }),
                ])
            })
            .collect();

        let table = Table::new(rows, [
            Constraint::Length(10),  // Severity
            Constraint::Percentage(50), // Title
            Constraint::Percentage(30), // Affected item
            Constraint::Length(10),  // Fixable
        ])
        .header(
            Row::new(vec!["Önem", "Başlık", "Hedef", "Düzeltilebilir"])
                .style(theme.header_style())
        )
        .block(
            Block::default()
                .title(" 🔍 Güvenlik Bulguları ")
                .title_style(theme.title_style())
                .borders(Borders::ALL)
                .border_style(theme.border_style())
                .style(theme.box_style()),
        )
        .highlight_style(theme.selected_item_style());

        frame.render_widget(table, area);
    }

    fn render_charts_view(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(50),  // Severity chart
                Constraint::Percentage(50),  // Scanner results chart
            ])
            .split(area);

        // Severity distribution chart
        self.render_severity_chart(frame, layout[0], theme);

        // Scanner results chart
        self.render_scanner_chart(frame, layout[1], theme);
    }

    fn render_severity_chart(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let (_, critical, high, medium, low) = self.get_summary_stats();

        let data = [
            ("Kritik", critical as u64),
            ("Yüksek", high as u64),
            ("Orta", medium as u64),
            ("Düşük", low as u64),
        ];

        let chart = BarChart::default()
            .block(
                Block::default()
                    .title(" 📊 Önem Seviyesi Dağılımı ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .data(&data)
            .bar_width(8)
            .bar_gap(2)
            .bar_style(theme.accent_style())
            .value_style(theme.list_item_style());

        frame.render_widget(chart, area);
    }

    fn render_scanner_chart(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let data: Vec<(&str, u64)> = self.scan_results
            .iter()
            .map(|result| {
                let short_name = result.scanner_name
                    .split_whitespace()
                    .next()
                    .unwrap_or(&result.scanner_name);
                (short_name, result.findings.len() as u64)
            })
            .collect();

        let chart = BarChart::default()
            .block(
                Block::default()
                    .title(" 📈 Scanner Bulgularının Dağılımı ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .data(&data)
            .bar_width(6)
            .bar_gap(1)
            .bar_style(theme.info_style())
            .value_style(theme.list_item_style());

        frame.render_widget(chart, area);
    }
}

#[async_trait::async_trait(?Send)]
impl AsyncKeyHandler for ReportsScreen {
    async fn handle_key_events(&mut self, key_event: KeyEvent) 
        -> Result<Option<ScreenAction>, PinGuardError> {
        
        if self.scan_results.is_empty() {
            match key_event.code {
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    Ok(Some(ScreenAction::SwitchScreen(ScreenType::Scanner)))
                }
                _ => Ok(None),
            }
        } else {
            match key_event.code {
                KeyCode::Tab => {
                    self.next_view();
                    Ok(None)
                }
                KeyCode::BackTab => {
                    self.previous_view();
                    Ok(None)
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    self.previous_result();
                    Ok(None)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.next_result();
                    Ok(None)
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    Ok(Some(ScreenAction::SwitchScreen(ScreenType::Scanner)))
                }
                KeyCode::Char('f') | KeyCode::Char('F') => {
                    Ok(Some(ScreenAction::SwitchScreen(ScreenType::Fixer)))
                }
                _ => Ok(None),
            }
        }
    }
}