use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Gauge};

use crate::core::errors::PinGuardError;
use crate::tui::theme::Theme;
use super::{Screen, AsyncKeyHandler, ScreenAction, ScreenType};

/// Scanner türleri
#[derive(Debug, Clone)]
struct ScannerType {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub estimated_time: String,
    pub last_run: Option<String>,
    pub severity: String,
}

/// Scanner ekranı
pub struct ScannerScreen {
    scanners: Vec<ScannerType>,
    list_state: ListState,
    scanning: bool,
    progress: f64,
    current_operation: String,
    results: Vec<String>,
}

impl ScannerScreen {
    pub fn new() -> Self {
        let scanners = vec![
            ScannerType {
                name: "🔍 Package Audit".to_string(),
                description: "Sistem paketlerini güvenlik açıkları için tarar".to_string(),
                enabled: true,
                estimated_time: "2-5 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
            },
            ScannerType {
                name: "🌐 Network Security".to_string(),
                description: "Ağ bağlantıları ve açık portları kontrol eder".to_string(),
                enabled: true,
                estimated_time: "1-3 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
            },
            ScannerType {
                name: "🔐 Permission Audit".to_string(),
                description: "Dosya ve dizin izinlerini kontrol eder".to_string(),
                enabled: true,
                estimated_time: "3-7 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
            },
            ScannerType {
                name: "👤 User Audit".to_string(),
                description: "Kullanıcı hesapları ve izinlerini inceler".to_string(),
                enabled: true,
                estimated_time: "1-2 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
            },
            ScannerType {
                name: "⚙️  Service Audit".to_string(),
                description: "Çalışan servisleri ve konfigürasyonları kontrol eder".to_string(),
                enabled: true,
                estimated_time: "2-4 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
            },
            ScannerType {
                name: "📋 Compliance Check".to_string(),
                description: "CIS, NIST gibi standartlara uygunluğu kontrol eder".to_string(),
                enabled: true,
                estimated_time: "5-10 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
            },
            ScannerType {
                name: "🐳 Container Security".to_string(),
                description: "Docker container'ları ve image'ları tarar".to_string(),
                enabled: true,
                estimated_time: "3-8 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
            },
            ScannerType {
                name: "🌍 Web Security".to_string(),
                description: "Web servisleri ve SSL sertifikalarını kontrol eder".to_string(),
                enabled: true,
                estimated_time: "2-5 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
            },
        ];

        let mut list_state = ListState::default();
        list_state.select(Some(0));

        Self {
            scanners,
            list_state,
            scanning: false,
            progress: 0.0,
            current_operation: String::new(),
            results: Vec::new(),
        }
    }

    fn next(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.scanners.len() - 1 {
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
                    self.scanners.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    async fn start_scan(&mut self) -> Result<Option<ScreenAction>, PinGuardError> {
        if let Some(i) = self.list_state.selected() {
            if let Some(scanner) = self.scanners.get(i) {
                if !scanner.enabled {
                    return Ok(Some(ScreenAction::SetStatus("Bu scanner şu anda kullanılamıyor".to_string())));
                }

                self.scanning = true;
                self.progress = 0.0;
                self.current_operation = format!("{} başlatılıyor...", scanner.name);
                self.results.clear();

                // TODO: Gerçek scan işlemini burada başlat
                // Şimdilik mock bir progress simüle edelim
                
                return Ok(Some(ScreenAction::SetStatus(format!("{} başlatıldı", scanner.name))));
            }
        }
        Ok(None)
    }

    async fn start_all_scans(&mut self) -> Result<Option<ScreenAction>, PinGuardError> {
        self.scanning = true;
        self.progress = 0.0;
        self.current_operation = "Tüm taramalar başlatılıyor...".to_string();
        self.results.clear();

        // TODO: Tüm scanner'ları sırayla çalıştır
        
        Ok(Some(ScreenAction::SetStatus("Tüm taramalar başlatıldı".to_string())))
    }

    fn stop_scan(&mut self) {
        self.scanning = false;
        self.current_operation = "Tarama durduruldu".to_string();
    }
}

impl Screen for ScannerScreen {
    fn title(&self) -> &str {
        "Security Scanner"
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        if self.scanning {
            self.render_scanning_view(frame, area, theme);
        } else {
            self.render_scanner_selection(frame, area, theme);
        }
    }

    fn help_text(&self) -> Vec<(&str, &str)> {
        if self.scanning {
            vec![
                ("S", "Stop scan"),
                ("ESC", "Back"),
            ]
        } else {
            vec![
                ("↑/↓", "Navigate"),
                ("Enter", "Run scanner"),
                ("A", "Run all"),
                ("R", "View reports"),
                ("ESC", "Back"),
            ]
        }
    }

    fn tick(&mut self) {
        if self.scanning {
            // Simulate progress
            self.progress += 0.02;
            if self.progress >= 1.0 {
                self.progress = 1.0;
                self.scanning = false;
                self.current_operation = "Tarama tamamlandı".to_string();
                self.results = vec![
                    "✓ 15 güvenlik kontrolü tamamlandı".to_string(),
                    "⚠ 3 orta seviye açık bulundu".to_string(),
                    "✗ 1 yüksek seviye açık bulundu".to_string(),
                ];
            }
        }
    }
}

#[async_trait::async_trait]
impl AsyncKeyHandler for ScannerScreen {
    async fn handle_key_events(&mut self, key_event: KeyEvent) 
        -> Result<Option<ScreenAction>, PinGuardError> {
        if self.scanning {
            match key_event.code {
                KeyCode::Char('s') | KeyCode::Char('S') => {
                    self.stop_scan();
                    Ok(Some(ScreenAction::SetStatus("Tarama durduruldu".to_string())))
                }
                _ => Ok(None),
            }
        } else {
            match key_event.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    self.previous();
                    Ok(None)
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    self.next();
                    Ok(None)
                }
                KeyCode::Enter | KeyCode::Char(' ') => {
                    self.start_scan().await
                }
                KeyCode::Char('a') | KeyCode::Char('A') => {
                    self.start_all_scans().await
                }
                KeyCode::Char('r') | KeyCode::Char('R') => {
                    Ok(Some(ScreenAction::SwitchScreen(ScreenType::Reports)))
                }
                _ => Ok(None),
            }
        }
    }
}

impl ScannerScreen {
    fn render_scanner_selection(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
            .split(area);

        // Sol taraf: Scanner listesi
        self.render_scanner_list(frame, layout[0], theme);

        // Sağ taraf: Seçili scanner detayları
        self.render_scanner_details(frame, layout[1], theme);
    }

    fn render_scanner_list(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let items: Vec<ListItem> = self
            .scanners
            .iter()
            .enumerate()
            .map(|(i, scanner)| {
                let style = if Some(i) == self.list_state.selected() {
                    theme.selected_item_style()
                } else if scanner.enabled {
                    theme.list_item_style()
                } else {
                    theme.muted_style()
                };

                let status = if scanner.enabled { "●" } else { "○" };
                let severity_style = theme.severity_style(&scanner.severity);
                
                let content = vec![
                    Line::from(vec![
                        Span::styled(format!(" {} ", status), theme.accent_style()),
                        Span::styled(&scanner.name, style),
                        Span::styled(
                            format!(" [{}]", scanner.severity),
                            severity_style
                        ),
                    ]),
                    Line::from(vec![
                        Span::styled("   ", style),
                        Span::styled(&scanner.description, theme.muted_style()),
                    ]),
                ];

                ListItem::new(content)
            })
            .collect();

        let block = Block::default()
            .title(" 🔍 Güvenlik Tarayıcıları ")
            .title_style(theme.title_style())
            .borders(Borders::ALL)
            .border_style(theme.focused_border_style())
            .style(theme.box_style());

        let list = List::new(items)
            .block(block)
            .highlight_style(theme.selected_item_style());

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_scanner_details(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let detail_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(8),     // Scanner detayları
                Constraint::Length(6),  // Son sonuçlar
            ])
            .split(area);

        // Scanner detayları
        if let Some(selected) = self.list_state.selected() {
            if let Some(scanner) = self.scanners.get(selected) {
                let details_text = vec![
                    Line::from(vec![
                        Span::styled("📝 İsim: ", theme.info_style()),
                        Span::styled(&scanner.name, theme.list_item_style()),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("📋 Açıklama:", theme.info_style()),
                    ]),
                    Line::from(vec![
                        Span::styled(&scanner.description, theme.muted_style()),
                    ]),
                    Line::from(""),
                    Line::from(vec![
                        Span::styled("⏱️  Tahmini Süre: ", theme.info_style()),
                        Span::styled(&scanner.estimated_time, theme.warning_style()),
                    ]),
                    Line::from(vec![
                        Span::styled("⚡ Önem Derecesi: ", theme.info_style()),
                        Span::styled(&scanner.severity, theme.severity_style(&scanner.severity)),
                    ]),
                    Line::from(vec![
                        Span::styled("🕐 Son Çalıştırma: ", theme.info_style()),
                        Span::styled(
                            scanner.last_run.as_deref().unwrap_or("Hiç çalıştırılmadı"),
                            if scanner.last_run.is_some() {
                                theme.success_style()
                            } else {
                                theme.muted_style()
                            }
                        ),
                    ]),
                ];

                let details = Paragraph::new(details_text)
                    .block(
                        Block::default()
                            .title(" 📋 Scanner Detayları ")
                            .title_style(theme.title_style())
                            .borders(Borders::ALL)
                            .border_style(theme.border_style())
                            .style(theme.box_style()),
                    )
                    .wrap(ratatui::widgets::Wrap { trim: true });

                frame.render_widget(details, detail_layout[0]);
            }
        }

        // Hızlı işlemler
        self.render_quick_actions(frame, detail_layout[1], theme);
    }

    fn render_quick_actions(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let actions_text = vec![
            Line::from(vec![
                Span::styled("⌨️  Hızlı İşlemler:", theme.info_style()),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Enter", theme.accent_style()),
                Span::styled(": Seçili tarayıcıyı çalıştır", theme.list_item_style()),
            ]),
            Line::from(vec![
                Span::styled("A", theme.accent_style()),
                Span::styled(": Tüm tarayıcıları çalıştır", theme.list_item_style()),
            ]),
            Line::from(vec![
                Span::styled("R", theme.accent_style()),
                Span::styled(": Raporları görüntüle", theme.list_item_style()),
            ]),
        ];

        let actions = Paragraph::new(actions_text)
            .block(
                Block::default()
                    .title(" ⚡ Hızlı İşlemler ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            );

        frame.render_widget(actions, area);
    }

    fn render_scanning_view(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(6),  // Progress
                Constraint::Min(0),     // Live output
                Constraint::Length(4),  // Controls
            ])
            .split(area);

        // Progress
        self.render_progress(frame, layout[0], theme);

        // Live output
        self.render_live_output(frame, layout[1], theme);

        // Controls
        self.render_scan_controls(frame, layout[2], theme);
    }

    fn render_progress(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
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
                    .title(" 📊 Tarama Durumu ")
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

    fn render_live_output(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let output_lines: Vec<Line> = self.results
            .iter()
            .map(|result| {
                if result.starts_with('✓') {
                    Line::from(Span::styled(result, theme.success_style()))
                } else if result.starts_with('⚠') {
                    Line::from(Span::styled(result, theme.warning_style()))
                } else if result.starts_with('✗') {
                    Line::from(Span::styled(result, theme.error_style()))
                } else {
                    Line::from(Span::styled(result, theme.list_item_style()))
                }
            })
            .collect();

        let output = Paragraph::new(output_lines)
            .block(
                Block::default()
                    .title(" 📝 Tarama Çıktısı ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(output, area);
    }

    fn render_scan_controls(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let controls_text = vec![
            Line::from(vec![
                Span::styled("🛑 ", theme.error_style()),
                Span::styled("S", theme.accent_style()),
                Span::styled(": Taramayı durdur   ", theme.list_item_style()),
                Span::styled("ESC", theme.accent_style()),
                Span::styled(": Geri dön", theme.list_item_style()),
            ]),
        ];

        let controls = Paragraph::new(controls_text)
            .block(
                Block::default()
                    .title(" ⌨️ Kontroller ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .alignment(Alignment::Center);

        frame.render_widget(controls, area);
    }
}