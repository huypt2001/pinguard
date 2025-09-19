use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Gauge, Wrap};

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

/// Scanner ekranı - Şimdilik simulated versiyonu
pub struct ScannerScreen {
    scanners: Vec<ScannerType>,
    list_state: ListState,
    scanning: bool,
    progress: f64,
    current_operation: String,
    results: Vec<String>,
    scan_count: u32,
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
                description: "Sistem izinlerini ve dosya güvenliğini kontrol eder".to_string(),
                enabled: true,
                estimated_time: "3-7 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
            },
            ScannerType {
                name: "👤 User Audit".to_string(),
                description: "Kullanıcı hesapları ve yetkileri tarar".to_string(),
                enabled: true,
                estimated_time: "1-2 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
            },
            ScannerType {
                name: "⚙️ Service Audit".to_string(),
                description: "Çalışan servisleri ve güvenlik ayarlarını kontrol eder".to_string(),
                enabled: true,
                estimated_time: "2-4 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
            },
            ScannerType {
                name: "🐳 Container Security".to_string(),
                description: "Docker konteynerlerini güvenlik açıkları için tarar".to_string(),
                enabled: true,
                estimated_time: "3-5 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
            },
            ScannerType {
                name: "🌍 Web Security".to_string(),
                description: "Web servislerini ve SSL/TLS yapılandırmasını kontrol eder".to_string(),
                enabled: true,
                estimated_time: "2-6 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
            },
            ScannerType {
                name: "📋 Compliance Check".to_string(),
                description: "Sistem güvenlik standartlarına uygunluk kontrolü".to_string(),
                enabled: true,
                estimated_time: "5-10 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
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
            scan_count: 0,
        }
    }

    /// Simulated scanner çalıştır
    fn run_simulated_scan(&mut self, scanner_index: usize) {
        if scanner_index >= self.scanners.len() {
            return;
        }

        self.scanning = true;
        self.progress = 0.0;
        self.current_operation = format!("Başlatılıyor: {}", self.scanners[scanner_index].name);
        self.scan_count += 1;

        // Başlangıç mesajı
        self.results.clear();
        self.results.push(format!("🔄 {} taraması başlatıldı...", self.scanners[scanner_index].name));
        
        // Simulated sonuçlar
        use rand::Rng;
        let mut rng = rand::thread_rng();
        
        let findings_count = rng.gen_range(0..15);
        let critical_count = rng.gen_range(0..3);
        let high_count = rng.gen_range(0..5);
        let medium_count = rng.gen_range(1..8);
        
        self.results.push(format!("✅ Tarama tamamlandı"));
        self.results.push(format!("📊 {} toplam bulgular", findings_count));
        
        if critical_count > 0 {
            self.results.push(format!("🔴 {} CRITICAL sorun bulundu!", critical_count));
        }
        if high_count > 0 {
            self.results.push(format!("🟠 {} HIGH risk sorun", high_count));
        }
        if medium_count > 0 {
            self.results.push(format!("🟡 {} MEDIUM risk sorun", medium_count));
        }
        
        // Örnek bulgular
        let sample_findings = vec![
            "Güncellenmeyen sistem paketleri",
            "Zayıf SSH yapılandırması", 
            "Açık portlar tespit edildi",
            "Yetkilendirilmemiş kullanıcı hesapları",
            "Güvenlik güncellemeleri eksik",
            "Firewall kuralları optimize edilmeli",
            "SSL sertifikası süresi dolmak üzere",
            "Şüpheli ağ bağlantıları",
        ];
        
        for i in 0..findings_count.min(5) {
            if let Some(finding) = sample_findings.get(i) {
                self.results.push(format!("• {}", finding));
            }
        }
        
        self.results.push(format!("⏱️ Tarama süresi: {}ms", rng.gen_range(500..5000)));
        self.current_operation = "Tarama tamamlandı ✅".to_string();
    }

    /// Tüm scanner'ları çalıştır (simulated)
    fn run_all_scans(&mut self) {
        self.scanning = true;
        self.progress = 0.0;
        self.current_operation = "Tüm taramalar başlatılıyor...".to_string();
        self.results.clear();
        self.scan_count += 1;

        let total_scanners = self.scanners.len();
        
        for (i, scanner) in self.scanners.iter().enumerate() {
            self.progress = (i + 1) as f64 / total_scanners as f64;
            
            use rand::Rng;
            let mut rng = rand::thread_rng();
            let findings = rng.gen_range(0..12);
            
            match findings {
                0..=2 => self.results.push(format!("✅ {}: Temiz", scanner.name)),
                3..=6 => self.results.push(format!("⚠️ {}: {} bulgular", scanner.name, findings)),
                7..=10 => self.results.push(format!("🟠 {}: {} sorun!", scanner.name, findings)),
                _ => self.results.push(format!("🔴 {}: {} kritik sorun!", scanner.name, findings)),
            }
        }

        self.current_operation = "Tüm taramalar tamamlandı ✅".to_string();
    }

    pub fn tick(&mut self) {
        // Gerçek zamanlı güncelleme simülasyonu
        if self.scanning && self.progress < 1.0 {
            self.progress += 0.05;
            if self.progress >= 1.0 {
                self.progress = 1.0;
                self.scanning = false;
            }
        }
    }
}

#[async_trait::async_trait]
impl AsyncKeyHandler for ScannerScreen {
    async fn handle_key_events(&mut self, key: KeyEvent) -> Result<Option<ScreenAction>, PinGuardError> {
        if self.scanning {
            // Tarama sırasında sadece ESC ile iptal
            if key.code == KeyCode::Esc {
                self.scanning = false;
                self.current_operation = "Tarama iptal edildi".to_string();
                return Ok(None);
            }
            return Ok(None);
        }

        match key.code {
            KeyCode::Up => {
                let selected = self.list_state.selected().unwrap_or(0);
                if selected > 0 {
                    self.list_state.select(Some(selected - 1));
                }
                Ok(None)
            }
            KeyCode::Down => {
                let selected = self.list_state.selected().unwrap_or(0);
                if selected < self.scanners.len() - 1 {
                    self.list_state.select(Some(selected + 1));
                }
                Ok(None)
            }
            KeyCode::Enter => {
                if let Some(selected) = self.list_state.selected() {
                    self.run_simulated_scan(selected);
                }
                Ok(None)
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                // Tüm taramaları çalıştır
                self.run_all_scans();
                Ok(None)
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                // Sonuçları temizle
                self.results.clear();
                self.progress = 0.0;
                self.current_operation.clear();
                Ok(None)
            }
            KeyCode::Esc => Ok(Some(ScreenAction::SwitchScreen(ScreenType::MainMenu))),
            _ => Ok(None),
        }
    }
}

impl Screen for ScannerScreen {
    fn title(&self) -> &str {
        "Security Scanners"
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        // Ana layout
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Sol panel: Scanner listesi
        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(10), Constraint::Length(3)])
            .split(chunks[0]);

        // Scanner listesi
        let items: Vec<ListItem> = self
            .scanners
            .iter()
            .enumerate()
            .map(|(_i, scanner)| {
                let severity_color = match scanner.severity.as_str() {
                    "Critical" => theme.error,
                    "High" => theme.warning,
                    "Medium" => theme.info,
                    _ => theme.fg,
                };

                let status = if self.scanning {
                    "🔄 Çalışıyor..."
                } else if self.scan_count > 0 {
                    "✅ Hazır"
                } else {
                    "⏳ Bekliyor"
                };

                ListItem::new(vec![
                    Line::from(vec![
                        Span::styled(&scanner.name, Style::default().fg(theme.accent).add_modifier(Modifier::BOLD)),
                        Span::raw("  "),
                        Span::styled(status, Style::default().fg(severity_color)),
                    ]),
                    Line::from(Span::styled(
                        &scanner.description,
                        Style::default().fg(theme.fg),
                    )),
                    Line::from(vec![
                        Span::styled("Süre: ", Style::default().fg(theme.fg)),
                        Span::styled(&scanner.estimated_time, Style::default().fg(theme.info)),
                        Span::raw("  "),
                        Span::styled("Risk: ", Style::default().fg(theme.fg)),
                        Span::styled(&scanner.severity, Style::default().fg(severity_color)),
                    ]),
                ])
            })
            .collect();

        let list = List::new(items)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("🔍 Security Scanners (Demo Mode)")
                    .border_style(Style::default().fg(theme.border)),
            )
            .highlight_style(
                Style::default()
                    .bg(theme.accent)
                    .fg(theme.bg)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        frame.render_stateful_widget(list, left_chunks[0], &mut self.list_state);

        // Kontroller
        let controls = Paragraph::new("Enter: Çalıştır | A: Tümünü çalıştır | R: Temizle | ESC: Geri")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Kontroller")
                    .border_style(Style::default().fg(theme.border)),
            )
            .style(Style::default().fg(theme.fg))
            .alignment(Alignment::Center);

        frame.render_widget(controls, left_chunks[1]);

        // Sağ panel: Sonuçlar ve progress
        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),  // Progress bar
                Constraint::Min(5),     // Sonuçlar
            ])
            .split(chunks[1]);

        // Progress bar
        if self.scanning {
            let progress = Gauge::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("🔄 Tarama Durumu")
                        .border_style(Style::default().fg(theme.border)),
                )
                .gauge_style(Style::default().fg(theme.accent))
                .percent((self.progress * 100.0) as u16)
                .label(self.current_operation.clone());

            frame.render_widget(progress, right_chunks[0]);
        } else {
            let status = Paragraph::new(
                if self.scan_count == 0 {
                    "Tarama yapmak için bir scanner seçin (Demo Mode)"
                } else {
                    "Tarama tamamlandı - Demo sonuçlar"
                }
            )
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("📊 Durum")
                    .border_style(Style::default().fg(theme.border)),
            )
            .style(Style::default().fg(theme.fg))
            .alignment(Alignment::Center);

            frame.render_widget(status, right_chunks[0]);
        }

        // Sonuçlar
        let results_text = if self.results.is_empty() {
            Text::from(vec![
                Line::from("🎮 DEMO MOD - Simulated Sonuçlar"),
                Line::from(""),
                Line::from("Kullanılabilir taramalar:"),
                Line::from("• Enter ile seçili taramayı çalıştır"),
                Line::from("• 'A' ile tüm taramaları çalıştır"),
                Line::from("• 'R' ile sonuçları temizle"),
                Line::from(""),
                Line::from("ℹ️ Gerçek scanner entegrasyonu yakında..."),
            ])
        } else {
            Text::from(
                self.results
                    .iter()
                    .map(|r| Line::from(r.as_str()))
                    .collect::<Vec<_>>()
            )
        };

        let results = Paragraph::new(results_text)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("📋 Tarama Sonuçları (Demo)")
                    .border_style(Style::default().fg(theme.border)),
            )
            .style(Style::default().fg(theme.fg))
            .wrap(Wrap { trim: true });

        frame.render_widget(results, right_chunks[1]);
    }
}