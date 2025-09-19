use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, List, ListItem, ListState, Gauge};

use crate::core::errors::PinGuardError;
use crate::core::config::Config;
use crate::fixers::{FixResult, manager::FixerManager};
use crate::scanners::{Finding, ScanResult};
use crate::tui::theme::Theme;
use super::{Screen, AsyncKeyHandler, ScreenAction, ScreenType};

/// Fixer operasyonu türü
#[derive(Debug, Clone)]
pub enum FixerOperation {
    ViewFindings,
    FixSelected,
    FixAll,
    DryRun,
}

/// Fix edilebilir finding
#[derive(Debug, Clone)]
pub struct FixableFinding {
    pub finding: Finding,
    pub available_fixers: Vec<String>,
    pub selected: bool,
}

pub struct FixerScreen {
    findings: Vec<FixableFinding>,
    list_state: ListState,
    fixer_manager: FixerManager,
    fixing: bool,
    progress: f64,
    current_operation: String,
    fix_results: Vec<FixResult>,
    mode: FixerOperation,
    show_details: bool,
    show_confirmation: bool,  // Fix onayı için dialog göster
    confirmation_message: String,  // Onay mesajı
}

impl FixerScreen {
    pub fn new() -> Self {
        let mut list_state = ListState::default();
        list_state.select(Some(0));

        Self {
            findings: Vec::new(),
            list_state,
            fixer_manager: FixerManager::new(),
            fixing: false,
            progress: 0.0,
            current_operation: String::new(),
            fix_results: Vec::new(),
            mode: FixerOperation::ViewFindings,
            show_details: false,
            show_confirmation: false,
            confirmation_message: String::new(),
        }
    }

    /// Scan sonuçlarından fix edilebilir finding'leri yükle
    pub fn load_findings(&mut self, scan_results: &[ScanResult]) {
        self.findings.clear();
        
        for result in scan_results {
            for finding in &result.findings {
                // Her finding için uygun fixer'ları bul
                let available_fixers = self.get_available_fixers(finding);
                
                if !available_fixers.is_empty() {
                    self.findings.push(FixableFinding {
                        finding: finding.clone(),
                        available_fixers,
                        selected: false,
                    });
                }
            }
        }

        // İlk item'ı seç
        if !self.findings.is_empty() {
            self.list_state.select(Some(0));
        }
    }

    fn get_available_fixers(&self, finding: &Finding) -> Vec<String> {
        // Basit fixer matching - gerçek implementasyon daha karmaşık olabilir
        let mut fixers = Vec::new();
        
        match finding.category {
            crate::scanners::Category::Permission => {
                fixers.push("Permission Fixer".to_string());
            }
            crate::scanners::Category::Service => {
                fixers.push("Service Hardener".to_string());
            }
            crate::scanners::Category::User => {
                fixers.push("User Policy Fixer".to_string());
            }
            crate::scanners::Category::Kernel => {
                fixers.push("Kernel Updater".to_string());
            }
            crate::scanners::Category::Network => {
                fixers.push("Firewall Configurator".to_string());
            }
            _ => {}
        }
        
        fixers
    }

    fn next(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.findings.len() - 1 {
                    0
                } else {
                    i + 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn previous(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i == 0 {
                    self.findings.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn toggle_selected(&mut self) {
        if let Some(i) = self.list_state.selected() {
            if let Some(finding) = self.findings.get_mut(i) {
                finding.selected = !finding.selected;
            }
        }
    }

    async fn fix_selected(&mut self) -> Result<Option<ScreenAction>, PinGuardError> {
        if let Some(i) = self.list_state.selected() {
            if let Some(fixable_finding) = self.findings.get(i) {
                self.fixing = true;
                self.progress = 0.0;
                self.current_operation = format!("Düzeltiliyor: {}", fixable_finding.finding.title);
                
                // Gerçek fix işlemini başlat
                let config = Config::default_config();
                match self.fixer_manager.fix_finding(&fixable_finding.finding, &config, true) { // auto_approve=true for TUI mode
                    Ok(result) => {
                        self.fix_results.push(result);
                        self.progress = 1.0;
                        self.fixing = false;
                        self.current_operation = "Düzeltme tamamlandı".to_string();
                        return Ok(Some(ScreenAction::SetStatus("Sorun başarıyla düzeltildi".to_string())));
                    }
                    Err(e) => {
                        self.fixing = false;
                        return Ok(Some(ScreenAction::SetStatus(format!("Düzeltme hatası: {}", e))));
                    }
                }
            }
        }
        Ok(None)
    }

    async fn fix_all_selected(&mut self) -> Result<Option<ScreenAction>, PinGuardError> {
        let selected_findings: Vec<_> = self.findings.iter()
            .filter(|f| f.selected)
            .cloned()  // Clone to avoid borrow issues
            .collect();

        if selected_findings.is_empty() {
            return Ok(Some(ScreenAction::SetStatus("Düzeltilecek sorun seçilmedi".to_string())));
        }

        self.fixing = true;
        self.progress = 0.0;
        self.current_operation = format!("{} sorun düzeltiliyor...", selected_findings.len());
        
        let config = Config::default_config();
        let mut success_count = 0;
        let total = selected_findings.len();

        for (i, fixable_finding) in selected_findings.iter().enumerate() {
            match self.fixer_manager.fix_finding(&fixable_finding.finding, &config, true) { // auto_approve=true for TUI mode
                Ok(result) => {
                    self.fix_results.push(result);
                    success_count += 1;
                }
                Err(_) => {
                    // Error handling - continue with next
                }
            }
            
            self.progress = (i + 1) as f64 / total as f64;
        }

        self.fixing = false;
        self.current_operation = format!("{}/{} sorun düzeltildi", success_count, total);
        
        Ok(Some(ScreenAction::SetStatus(format!("{} sorundan {} tanesi düzeltildi", total, success_count))))
    }
}

impl Screen for FixerScreen {
    fn title(&self) -> &str {
        "Security Fixer"
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        if self.show_confirmation {
            self.render_confirmation_dialog(frame, area, theme);
        } else if self.findings.is_empty() {
            self.render_empty_state(frame, area, theme);
        } else if self.fixing {
            self.render_fixing_view(frame, area, theme);
        } else {
            self.render_findings_list(frame, area, theme);
        }
    }

    fn help_text(&self) -> Vec<(&str, &str)> {
        if self.show_confirmation {
            vec![
                ("Y", "Confirm"),
                ("N/ESC", "Cancel"),
            ]
        } else if self.fixing {
            vec![
                ("ESC", "Back"),
            ]
        } else if self.findings.is_empty() {
            vec![
                ("R", "Refresh findings"),
                ("ESC", "Back"),
            ]
        } else {
            vec![
                ("↑/↓", "Navigate"),
                ("Space", "Select/Unselect"),
                ("Enter", "Fix selected"),
                ("A", "Fix all selected"),
                ("D", "Details"),
                ("ESC", "Back"),
            ]
        }
    }

    fn tick(&mut self) {
        // Progress updates handled by actual fix operations
    }
}

impl FixerScreen {
    fn render_empty_state(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let content = vec![
            Line::from("🛠️ Güvenlik Düzeltme Aracı"),
            Line::from(""),
            Line::from("Düzeltilebilir güvenlik sorunu bulunamadı."),
            Line::from(""),
            Line::from("Önce bir güvenlik taraması çalıştırın:"),
            Line::from("• F2 tuşuna basarak Scanner'a gidin"),
            Line::from("• Bir tarama çalıştırın"),
            Line::from("• Sonuçları görüntülemek için buraya geri dönün"),
            Line::from(""),
            Line::from(vec![
                Span::styled("R", theme.accent_style()),
                Span::styled(": Bulguları yenile", theme.list_item_style()),
            ]),
        ];

        let paragraph = Paragraph::new(content)
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

        frame.render_widget(paragraph, area);
    }

    fn render_findings_list(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        // Sol taraf: Finding listesi
        self.render_finding_list(frame, layout[0], theme);

        // Sağ taraf: Detaylar
        self.render_finding_details(frame, layout[1], theme);
    }

    fn render_finding_list(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let items: Vec<ListItem> = self
            .findings
            .iter()
            .enumerate()
            .map(|(i, fixable_finding)| {
                let style = if Some(i) == self.list_state.selected() {
                    theme.selected_item_style()
                } else {
                    theme.list_item_style()
                };

                let check = if fixable_finding.selected { "☑" } else { "☐" };
                let severity_style = theme.severity_style(&format!("{:?}", fixable_finding.finding.severity));
                
                let content = vec![
                    Line::from(vec![
                        Span::styled(format!(" {} ", check), theme.accent_style()),
                        Span::styled(&fixable_finding.finding.title, style),
                    ]),
                    Line::from(vec![
                        Span::styled("   ", style),
                        Span::styled(
                            format!("{:?} | {}", fixable_finding.finding.severity, fixable_finding.finding.affected_item),
                            severity_style
                        ),
                    ]),
                ];

                ListItem::new(content)
            })
            .collect();

        let block = Block::default()
            .title(format!(" 🔧 Düzeltilebilir Sorunlar ({}) ", self.findings.len()))
            .title_style(theme.title_style())
            .borders(Borders::ALL)
            .border_style(theme.focused_border_style())
            .style(theme.box_style());

        let list = List::new(items)
            .block(block)
            .highlight_style(theme.selected_item_style());

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_finding_details(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),     // Detaylar
                Constraint::Length(6),  // Mevcut fixer'lar
            ])
            .split(area);

        // Finding detayları
        if let Some(selected) = self.list_state.selected() {
            if let Some(fixable_finding) = self.findings.get(selected) {
                let finding = &fixable_finding.finding;
                
                // Format strings to avoid borrow issues
                let severity_str = format!("{:?}", finding.severity);
                let category_str = format!("{:?}", finding.category);
                
                let details_text = vec![
                    Line::from(vec![
                        Span::styled("🎯 Başlık: ", theme.info_style()),
                        Span::styled(&finding.title, theme.list_item_style()),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("📋 Açıklama:", theme.info_style()),
                    ]),
                    Line::from(vec![
                        Span::styled(&finding.description, theme.muted_style()),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("⚡ Önem: ", theme.info_style()),
                        Span::styled(&severity_str, theme.severity_style(&severity_str)),
                    ]),
                    Line::from(vec![
                        Span::styled("📂 Kategori: ", theme.info_style()),
                        Span::styled(&category_str, theme.info_style()),
                    ]),
                    Line::from(vec![
                        Span::styled("🎯 Hedef: ", theme.info_style()),
                        Span::styled(&finding.affected_item, theme.warning_style()),
                    ]),
                ];

                let details = Paragraph::new(details_text)
                    .block(
                        Block::default()
                            .title(" � Sorun Detayları ")
                            .title_style(theme.title_style())
                            .borders(Borders::ALL)
                            .border_style(theme.border_style())
                            .style(theme.box_style()),
                    )
                    .wrap(ratatui::widgets::Wrap { trim: true });

                frame.render_widget(details, layout[0]);

                // Mevcut fixer'lar
                self.render_available_fixers(frame, layout[1], theme, &fixable_finding.available_fixers);
            }
        }
    }

    fn render_available_fixers(&self, frame: &mut Frame, area: Rect, theme: &Theme, fixers: &[String]) {
        let mut fixer_lines = vec![
            Line::from(vec![
                Span::styled("�🛠️ Mevcut Düzeltici Araçlar:", theme.info_style()),
            ]),
            Line::from(""),
        ];

        for fixer in fixers {
            fixer_lines.push(Line::from(vec![
                Span::styled("• ", theme.accent_style()),
                Span::styled(fixer, theme.success_style()),
            ]));
        }

        if fixer_lines.len() == 2 { // Only header
            fixer_lines.push(Line::from(vec![
                Span::styled("❌ Bu sorun için düzeltici araç bulunamadı", theme.error_style()),
            ]));
        }

        let fixers_widget = Paragraph::new(fixer_lines)
            .block(
                Block::default()
                    .title(" 🔧 Düzeltici Araçlar ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            );

        frame.render_widget(fixers_widget, area);
    }

    fn render_fixing_view(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),  // Progress
                Constraint::Min(0),     // Results
            ])
            .split(area);

        // Progress
        self.render_fix_progress(frame, layout[0], theme);

        // Results
        self.render_fix_results(frame, layout[1], theme);
    }

    fn render_fix_progress(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let progress_text = vec![
            Line::from(vec![
                Span::styled("🔄 İşlem: ", theme.info_style()),
                Span::styled(&self.current_operation, theme.list_item_style()),
            ]),
            Line::from(""),
        ];

        let progress_info = Paragraph::new(progress_text)
            .block(
                Block::default()
                    .title(" 🛠️ Düzeltme Durumu ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            );

        frame.render_widget(progress_info, area);

        // Progress bar
        let progress_area = Rect {
            x: area.x + 2,
            y: area.y + 3,
            width: area.width - 4,
            height: 1,
        };

        let gauge = Gauge::default()
            .block(Block::default())
            .gauge_style(theme.progress_style())
            .percent((self.progress * 100.0) as u16)
            .label(format!("{:.1}%", self.progress * 100.0));

        frame.render_widget(gauge, progress_area);
    }

    fn render_fix_results(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let result_lines: Vec<Line> = self.fix_results
            .iter()
            .map(|result| {
                match result.status {
                    crate::fixers::FixStatus::Success => {
                        Line::from(vec![
                            Span::styled("✅ ", theme.success_style()),
                            Span::styled(&result.finding_id, theme.list_item_style()),
                            Span::styled(" - Başarıyla düzeltildi", theme.success_style()),
                        ])
                    }
                    crate::fixers::FixStatus::Failed => {
                        Line::from(vec![
                            Span::styled("❌ ", theme.error_style()),
                            Span::styled(&result.finding_id, theme.list_item_style()),
                            Span::styled(" - Düzeltme başarısız", theme.error_style()),
                        ])
                    }
                    crate::fixers::FixStatus::RequiresUserAction => {
                        Line::from(vec![
                            Span::styled("⚠️ ", theme.warning_style()),
                            Span::styled(&result.finding_id, theme.list_item_style()),
                            Span::styled(" - Kullanıcı müdahalesi gerekli", theme.warning_style()),
                        ])
                    }
                    crate::fixers::FixStatus::RequiresReboot => {
                        Line::from(vec![
                            Span::styled("🔄 ", theme.info_style()),
                            Span::styled(&result.finding_id, theme.list_item_style()),
                            Span::styled(" - Yeniden başlatma gerekli", theme.info_style()),
                        ])
                    }
                    _ => {
                        Line::from(vec![
                            Span::styled("ℹ️ ", theme.info_style()),
                            Span::styled(&result.finding_id, theme.list_item_style()),
                            Span::styled(" - İşleniyor", theme.info_style()),
                        ])
                    }
                }
            })
            .collect();

        let results = Paragraph::new(result_lines)
            .block(
                Block::default()
                    .title(" 📋 Düzeltme Sonuçları ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(results, area);
    }
}

#[async_trait::async_trait(?Send)]
impl AsyncKeyHandler for FixerScreen {
    async fn handle_key_events(&mut self, key_event: KeyEvent) 
        -> Result<Option<ScreenAction>, PinGuardError> {
        
        if self.show_confirmation {
            // Confirmation dialog mode
            match key_event.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    self.show_confirmation = false;
                    // Proceed with fix
                    if self.list_state.selected().is_some() {
                        self.fix_selected().await
                    } else {
                        Ok(None)
                    }
                }
                KeyCode::Char('n') | KeyCode::Char('N') | KeyCode::Esc => {
                    self.show_confirmation = false;
                    Ok(Some(ScreenAction::SetStatus("Fix işlemi iptal edildi".to_string())))
                }
                _ => Ok(None),
            }
        } else if self.fixing {
            // Fixing mode - limited interactions
            match key_event.code {
                KeyCode::Esc => {
                    self.fixing = false;
                    Ok(Some(ScreenAction::SetStatus("Düzeltme işlemi iptal edildi".to_string())))
                }
                _ => Ok(None),
            }
        } else if self.findings.is_empty() {
            // Empty state
            match key_event.code {
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    // TODO: Refresh findings from scan results
                    Ok(Some(ScreenAction::SetStatus("Bulgular yenileniyor...".to_string())))
                }
                _ => Ok(None),
            }
        } else {
            // Normal operation mode
            match key_event.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.previous();
                    Ok(None)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.next();
                    Ok(None)
                }
                KeyCode::Char(' ') => {
                    self.toggle_selected();
                    Ok(None)
                }
                KeyCode::Enter => {
                    // Show confirmation dialog before fixing
                    if let Some(i) = self.list_state.selected() {
                        if let Some(finding) = self.findings.get(i) {
                            self.confirmation_message = format!(
                                "Bu sorunu düzeltmek istediğinizden emin misiniz?\n\n'{}'\n\nFix uygulanacak: {}",
                                finding.finding.title,
                                finding.available_fixers.join(", ")
                            );
                            self.show_confirmation = true;
                        }
                    }
                    Ok(None)
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    self.fix_all_selected().await
                }
                KeyCode::Char('d') | KeyCode::Char('D') => {
                    self.show_details = !self.show_details;
                    Ok(None)
                }
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    Ok(Some(ScreenAction::SwitchScreen(ScreenType::Scanner)))
                }
                _ => Ok(None),
            }
        }
    }
}

impl FixerScreen {
    fn render_confirmation_dialog(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        // Create centered popup
        let popup_area = centered_rect(70, 40, area);
        
        // Clear background
        frame.render_widget(ratatui::widgets::Clear, popup_area);
        
        let confirmation_text = vec![
            Line::from(""),
            Line::from(vec![
                Span::styled("🔧 Fix Onayı", theme.title_style()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled(&self.confirmation_message, theme.list_item_style()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Devam etmek istiyor musunuz?", theme.warning_style()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("[Y] Evet  [N] Hayır  [ESC] İptal", theme.accent_style()),
            ]),
        ];

        let confirmation_popup = Paragraph::new(confirmation_text)
            .block(
                Block::default()
                    .title(" ⚠️  Onay Gerekli ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.warning_style())
                    .style(theme.box_style()),
            )
            .alignment(ratatui::layout::Alignment::Center)
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(confirmation_popup, popup_area);
    }
}

// Helper function for centered popup
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}