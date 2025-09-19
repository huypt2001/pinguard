use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Gauge, Wrap};

use crate::core::errors::PinGuardError;
use crate::core::config::Config;
use crate::scanners::{manager::ScannerManager, ScanResult, ScanStatus};
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
    scanner_manager: ScannerManager,
    scan_results: Vec<ScanResult>,
}

impl ScannerScreen {
    pub fn new() -> Self {
        let scanner_manager = ScannerManager::new();
        
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
            scanner_manager,
            scan_results: Vec::new(),
        }
    }

    /// Gerçek scanner çalıştır
    async fn run_real_scan(&mut self, scanner_index: usize) -> Result<(), PinGuardError> {
        if scanner_index >= self.scanners.len() {
            return Err(PinGuardError::config("Invalid scanner index"));
        }

        self.scanning = true;
        self.progress = 0.0;
        self.current_operation = format!("Starting {}...", self.scanners[scanner_index].name);

        // Default config - normalde bu config dosyasından gelir
        let config = Config::default_config();

        // Scanner name mapping
        let scanner_name = match scanner_index {
            0 => "Package Audit",
            1 => "Network Audit", 
            2 => "Permission Audit",
            3 => "User Audit",
            4 => "Service Audit",
            5 => "Container Security",
            6 => "Web Security",
            7 => "Compliance Scanner",
            _ => return Err(PinGuardError::config("Unknown scanner")),
        };

        self.current_operation = format!("Running {}...", scanner_name);
        self.progress = 0.3;

        // Gerçek scanner çalıştır
        match self.scanner_manager.run_specific_scan(scanner_name, &config) {
            Ok(result) => {
                self.progress = 1.0;
                
                // Sonuçları formatla
                let findings_count = result.findings.len();
                let critical_count = result.findings.iter()
                    .filter(|f| matches!(f.severity, crate::scanners::Severity::Critical))
                    .count();
                let high_count = result.findings.iter()
                    .filter(|f| matches!(f.severity, crate::scanners::Severity::High))
                    .count();

                self.results.clear();
                self.results.push(format!("✅ {} tamamlandı", scanner_name));
                self.results.push(format!("📊 {} bulgular bulundu", findings_count));
                if critical_count > 0 {
                    self.results.push(format!("🔴 {} kritik sorun", critical_count));
                }
                if high_count > 0 {
                    self.results.push(format!("🟠 {} yüksek riskli sorun", high_count));
                }
                self.results.push(format!("⏱️ Süre: {}ms", result.metadata.duration_ms));

                // Önemli bulguları ekle
                for finding in result.findings.iter().take(5) {
                    self.results.push(format!(
                        "• {}: {}", 
                        severity_to_string(&finding.severity),
                        finding.title
                    ));
                }

                self.scan_results.push(result);
                self.current_operation = "Tarama tamamlandı".to_string();
            },
            Err(e) => {
                self.results.clear();
                self.results.push(format!("❌ Tarama başarısız: {}", e));
                self.current_operation = "Tarama başarısız".to_string();
            }
        }

        self.scanning = false;
        Ok(())
    }

    /// Tüm scanner'ları çalıştır
    async fn run_all_scans(&mut self) -> Result<(), PinGuardError> {
        self.scanning = true;
        self.progress = 0.0;
        self.current_operation = "Tüm taramalar başlatılıyor...".to_string();
        self.results.clear();

        let config = Config::default_config();
        let results = self.scanner_manager.run_all_scans(&config);
        
        let total_scanners = results.len();
        let mut completed = 0;

        for result in results {
            completed += 1;
            self.progress = completed as f64 / total_scanners as f64;
            
            match result.status {
                ScanStatus::Success => {
                    let findings = result.findings.len();
                    self.results.push(format!("✅ {}: {} bulgular", result.scanner_name, findings));
                },
                ScanStatus::Error(ref e) => {
                    self.results.push(format!("❌ {}: {}", result.scanner_name, e));
                },
                ScanStatus::Warning => {
                    self.results.push(format!("⚠️ {}: Uyarılar var", result.scanner_name));
                },
                ScanStatus::Skipped(ref reason) => {
                    self.results.push(format!("⏭️ {}: {}", result.scanner_name, reason));
                }
            }
            
            self.scan_results.push(result);
        }

        self.current_operation = "Tüm taramalar tamamlandı".to_string();
        self.scanning = false;
        Ok(())
    }

    pub fn tick(&mut self) {
        // Gerçek zamanlı güncelleme simülasyonu
        if self.scanning && self.progress < 1.0 {
            self.progress += 0.02;
            if self.progress > 1.0 {
                self.progress = 1.0;
            }
        }
    }
}

// Helper function for severity display
fn severity_to_string(severity: &crate::scanners::Severity) -> String {
    match severity {
        crate::scanners::Severity::Info => "INFO".to_string(),
        crate::scanners::Severity::Low => "LOW".to_string(),
        crate::scanners::Severity::Medium => "MEDIUM".to_string(),
        crate::scanners::Severity::High => "HIGH".to_string(),
        crate::scanners::Severity::Critical => "CRITICAL".to_string(),
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
                return Ok(Some(ScreenAction::SwitchScreen(ScreenType::MainMenu)));
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
                    if let Err(e) = self.run_real_scan(selected).await {
                        self.results.clear();
                        self.results.push(format!("❌ Hata: {}", e));
                    }
                }
                Ok(None)
            }
            KeyCode::Char('a') | KeyCode::Char('A') => {
                // Tüm taramaları çalıştır
                if let Err(e) = self.run_all_scans().await {
                    self.results.clear();
                    self.results.push(format!("❌ Hata: {}", e));
                }
                Ok(None)
            }
            KeyCode::Char('r') | KeyCode::Char('R') => {
                // Sonuçları temizle
                self.results.clear();
                self.scan_results.clear();
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
            .map(|(i, scanner)| {
                let severity_color = match scanner.severity.as_str() {
                    "Critical" => theme.error,
                    "High" => theme.warning,
                    "Medium" => theme.info,
                    _ => theme.fg,
                };

                let status = if self.scanning {
                    "🔄 Çalışıyor..."
                } else if !self.scan_results.is_empty() {
                    "✅ Tamamlandı"
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
                    .title("🔍 Security Scanners")
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
                if self.scan_results.is_empty() {
                    "Tarama yapmak için bir scanner seçin"
                } else {
                    "Son tarama tamamlandı"
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
                Line::from("Henüz tarama yapılmadı."),
                Line::from(""),
                Line::from("Kullanılabilir taramalar:"),
                Line::from("• Enter ile seçili taramayı çalıştır"),
                Line::from("• 'A' ile tüm taramaları çalıştır"),
                Line::from("• 'R' ile sonuçları temizle"),
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
                    .title("📋 Tarama Sonuçları")
                    .border_style(Style::default().fg(theme.border)),
            )
            .style(Style::default().fg(theme.fg))
            .wrap(Wrap { trim: true });

        frame.render_widget(results, right_chunks[1]);
    }
}