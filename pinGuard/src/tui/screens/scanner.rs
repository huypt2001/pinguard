use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Gauge, Sparkline};
use std::time::{Duration, Instant, SystemTime};

use crate::core::errors::PinGuardError;
use crate::core::config::Config;
use crate::scanners::{ScanResult, ScanStatus, manager::ScannerManager};
use crate::tui::theme::Theme;
use super::{Screen, AsyncKeyHandler, ScreenAction, ScreenType};

/// Scanner türleri
#[derive(Debug, Clone)]
struct ScannerType {
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub estimated_time: String,
    pub last_run: Option<SystemTime>,
    pub severity: String,
    pub scanner_key: String, // Gerçek scanner'ı tanımlamak için
}

/// Scanner ekranı
pub struct ScannerScreen {
    scanners: Vec<ScannerType>,
    list_state: ListState,
    scanning: bool,
    progress: f64,
    current_operation: String,
    results: Vec<String>,
    scan_results: Vec<ScanResult>,
    scanner_manager: ScannerManager,
    scan_start_time: Option<Instant>,
    current_scanner_index: Option<usize>,
    completed_scanners: usize,
    total_scanners: usize,
    progress_animation: Vec<f64>,
    last_update: Instant,
    scan_step: usize, // Hangi aşamada olduğumuz
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
                scanner_key: "package_audit".to_string(),
            },
            ScannerType {
                name: "🌐 Network Security".to_string(),
                description: "Ağ bağlantıları ve açık portları kontrol eder".to_string(),
                enabled: true,
                estimated_time: "1-3 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
                scanner_key: "network_audit".to_string(),
            },
            ScannerType {
                name: "🔐 Permission Audit".to_string(),
                description: "Dosya ve dizin izinlerini kontrol eder".to_string(),
                enabled: true,
                estimated_time: "3-7 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
                scanner_key: "permission_audit".to_string(),
            },
            ScannerType {
                name: "👤 User Audit".to_string(),
                description: "Kullanıcı hesapları ve izinlerini inceler".to_string(),
                enabled: true,
                estimated_time: "1-2 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
                scanner_key: "user_audit".to_string(),
            },
            ScannerType {
                name: "⚙️  Service Audit".to_string(),
                description: "Çalışan servisleri ve konfigürasyonları kontrol eder".to_string(),
                enabled: true,
                estimated_time: "2-4 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
                scanner_key: "service_audit".to_string(),
            },
            ScannerType {
                name: "📋 Compliance Check".to_string(),
                description: "CIS, NIST gibi standartlara uygunluğu kontrol eder".to_string(),
                enabled: true,
                estimated_time: "5-10 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
                scanner_key: "compliance".to_string(),
            },
            ScannerType {
                name: "🐳 Container Security".to_string(),
                description: "Docker container'ları ve image'ları tarar".to_string(),
                enabled: true,
                estimated_time: "3-8 dakika".to_string(),
                last_run: None,
                severity: "High".to_string(),
                scanner_key: "container_security".to_string(),
            },
            ScannerType {
                name: "🌍 Web Security".to_string(),
                description: "Web servisleri ve SSL sertifikalarını kontrol eder".to_string(),
                enabled: true,
                estimated_time: "2-5 dakika".to_string(),
                last_run: None,
                severity: "Medium".to_string(),
                scanner_key: "web_security".to_string(),
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
            scan_results: Vec::new(),
            scanner_manager: ScannerManager::new(),
            scan_start_time: None,
            current_scanner_index: None,
            completed_scanners: 0,
            total_scanners: 0,
            progress_animation: vec![0.0; 50],
            last_update: Instant::now(),
            scan_step: 0,
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
            if let Some(scanner) = self.scanners.get(i).cloned() {  // Clone to avoid borrow conflict
                if !scanner.enabled {
                    return Ok(Some(ScreenAction::SetStatus("Bu scanner şu anda kullanılamıyor".to_string())));
                }

                self.scanning = true;
                self.progress = 0.0;
                self.current_operation = format!("{} başlatılıyor...", scanner.name);
                self.results.clear();
                self.scan_results.clear();
                self.scan_start_time = Some(Instant::now());
                self.current_scanner_index = Some(i);
                self.completed_scanners = 0;
                self.total_scanners = 1;
                self.scan_step = 0;

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
        self.scan_results.clear();
        self.scan_start_time = Some(Instant::now());
        self.current_scanner_index = None;
        self.completed_scanners = 0;
        self.total_scanners = self.scanners.iter().filter(|s| s.enabled).count();
        self.scan_step = 0;
        
        Ok(Some(ScreenAction::SetStatus("Tüm taramalar başlatıldı".to_string())))
    }

    fn stop_scan(&mut self) {
        self.scanning = false;
        self.current_operation = "Tarama durduruldu".to_string();
        self.scan_start_time = None;
        self.current_scanner_index = None;
        self.scan_step = 0;
    }

    fn clear_results(&mut self) {
        self.scan_results.clear();
        self.results.clear();
        self.scan_start_time = None;
        self.current_scanner_index = None;
        self.completed_scanners = 0;
        self.scan_step = 0;
        self.progress = 0.0;
        self.current_operation = "Hazır".to_string();
    }

    // Scan sonuçlarını başka ekranlarda kullanmak için getter
    pub fn get_scan_results(&self) -> &[ScanResult] {
        &self.scan_results
    }

    // Bu fonksiyon gerçek scanner işlemlerini adım adım çalıştırır
    fn process_scan_step(&mut self) {
        if !self.scanning {
            return;
        }

        // Progress animasyonu güncelle
        let now = Instant::now();
        if now.duration_since(self.last_update) < Duration::from_millis(500) {
            return; // Çok sık güncelleme yapma
        }
        self.last_update = now;
        
        // Progress bar animasyonu
        self.progress_animation.remove(0);
        let variation = (now.elapsed().as_millis() % 100) as f64 / 1000.0;
        self.progress_animation.push(self.progress + variation);

        // Gerçek scanner işlemlerini adım adım çalıştır
        match self.scan_step {
            0 => {
                // İlk adım: Taramaya başla
                self.current_operation = "Sistem taraması başlatılıyor...".to_string();
                self.scan_step = 1;
                self.progress = 0.1;
            }
            1 => {
                // İkinci adım: Gerçek scan işlemini çalıştır
                if let Some(index) = self.current_scanner_index {
                    if let Some(scanner) = self.scanners.get(index) {
                        self.current_operation = format!("{} çalıştırılıyor...", scanner.name);
                        
                        // Scanner key'i klon et
                        let scanner_key = scanner.scanner_key.clone();
                        let scanner_name = scanner.name.clone();
                        
                        // Gerçek scanner'ı çalıştır
                        match self.run_single_scanner(&scanner_key) {
                            Ok(_) => {
                                self.scan_step = 2;
                                self.progress = 0.9;
                            }
                            Err(_) => {
                                self.results.push(format!("❌ {}: Tarama hatası", scanner_name));
                                self.scan_step = 3;
                                self.progress = 1.0;
                            }
                        }
                    }
                } else {
                    // Tüm scanner'ları çalıştır
                    self.current_operation = "Tüm tarayıcılar çalıştırılıyor...".to_string();
                    match self.run_all_scanners() {
                        Ok(_) => {
                            self.scan_step = 2;
                            self.progress = 0.9;
                        }
                        Err(_) => {
                            self.results.push("❌ Tarama hatası oluştu".to_string());
                            self.scan_step = 3;
                            self.progress = 1.0;
                        }
                    }
                }
            }
            2 => {
                // Son adım: Sonuçları işle
                self.current_operation = "Sonuçlar işleniyor...".to_string();
                self.progress = 1.0;
                self.scan_step = 3;
            }
            _ => {
                // Tarama tamamlandı
                self.scanning = false;
                self.current_operation = "Tarama tamamlandı! Sonuçları görüntülemek için 'R' tuşuna basın".to_string();
                self.progress = 1.0;
                
                // Sonuçları kalıcı olarak kaydet
                self.save_scan_results();
                
                // Last run tarihini güncelle
                self.update_last_run_dates();
                
                // Scan completion bildirimi
                if !self.scan_results.is_empty() {
                    let total_findings = self.scan_results.iter().map(|r| r.findings.len()).sum::<usize>();
                    self.results.push(format!("🎉 Tarama tamamlandı! {} bulgular bulundu", total_findings));
                } else {
                    self.results.push("🎉 Tarama tamamlandı! Hiç bulgular bulunamadı".to_string());
                }
            }
        }
    }

    // Gerçek scanner işlemlerini çalıştırmak için yardımcı fonksiyonlar
    fn run_single_scanner(&mut self, scanner_key: &str) -> Result<(), PinGuardError> {
        // Varsayılan config kullan
        let config = Config::default_config();
        
        self.results.push(format!("🔄 {} başlatılıyor...", scanner_key));
        
        // Gerçek scanner'ı çalıştır - bu blocking olabilir ama kısa sürede tamamlanmalı
        match self.scanner_manager.run_specific_scan(scanner_key, &config) {
            Ok(result) => {
                self.process_scan_result(result);
                self.results.push(format!("✅ {} tamamlandı", scanner_key));
            }
            Err(e) => {
                let error_msg = format!("❌ {}: Hata - {}", scanner_key, e);
                self.results.push(error_msg);
                return Err(PinGuardError::config(format!("Scan failed: {}", e)));
            }
        }
        
        Ok(())
    }

    fn run_all_scanners(&mut self) -> Result<(), PinGuardError> {
        // Varsayılan config kullan
        let config = Config::default_config();
        
        self.results.push("🔄 Tüm tarayıcılar başlatılıyor...".to_string());
        
        // Sadece enabled scanner'ları çalıştır
        let enabled_scanners: Vec<String> = self.scanners
            .iter()
            .filter(|s| s.enabled)
            .map(|s| s.scanner_key.clone())
            .collect();
        
        for scanner_key in enabled_scanners {
            self.results.push(format!("🔄 {} çalıştırılıyor...", scanner_key));
            
            match self.scanner_manager.run_specific_scan(&scanner_key, &config) {
                Ok(result) => {
                    self.process_scan_result(result);
                    self.results.push(format!("✅ {} tamamlandı", scanner_key));
                    self.completed_scanners += 1;
                }
                Err(e) => {
                    let error_msg = format!("❌ {}: Hata - {}", scanner_key, e);
                    self.results.push(error_msg);
                    // Hata olsa bile diğer scanner'lara devam et
                    self.completed_scanners += 1;
                }
            }
        }
        
        Ok(())
    }

    fn process_scan_result(&mut self, result: ScanResult) {
        self.scan_results.push(result.clone());
        
        match result.status {
            ScanStatus::Success => {
                let finding_count = result.findings.len();
                if finding_count == 0 {
                    self.results.push(format!("✅ {}: Hiç sorun bulunamadı", result.scanner_name));
                } else {
                    self.results.push(format!("⚠️ {}: {} güvenlik sorunu bulundu", result.scanner_name, finding_count));
                    
                    // Kritik ve yüksek öncelikli bulguları listele
                    let critical_count = result.get_critical_findings().len();
                    let high_count = result.get_high_findings().len();
                    
                    if critical_count > 0 {
                        self.results.push(format!("  🔴 {} kritik sorun", critical_count));
                    }
                    if high_count > 0 {
                        self.results.push(format!("  🟠 {} yüksek öncelikli sorun", high_count));
                    }
                }
            }
            ScanStatus::Warning => {
                self.results.push(format!("⚠️ {}: Uyarılar ile tamamlandı", result.scanner_name));
            }
            ScanStatus::Error(ref msg) => {
                self.results.push(format!("❌ {}: Hata - {}", result.scanner_name, msg));
            }
            ScanStatus::Skipped(ref reason) => {
                self.results.push(format!("⏭️ {}: Atlandı - {}", result.scanner_name, reason));
            }
        }
        
        // Progress güncelle (basit increment) - ama scanning state'i değiştirme
        self.progress += 0.12; // Her scanner için yaklaşık %12 artır
        if self.progress >= 1.0 {
            self.progress = 1.0;
            // scanning state'ini burada değiştirme - step-based sistemde halledilecek
        }
    }

    fn save_scan_results(&mut self) {
        // Scan sonuçlarını kalıcı olarak kaydet
        use std::fs;
        use std::time::SystemTime;
        
        if self.scan_results.is_empty() {
            return;
        }
        
        // Scan history dosyasına yaz
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let scan_summary = format!(
            "Scan completed at {}: {} scanners, {} total findings\n",
            timestamp,
            self.scan_results.len(),
            self.scan_results.iter().map(|r| r.findings.len()).sum::<usize>()
        );
        
        // scan_history.txt dosyasına ekle
        if let Err(e) = fs::write("scan_history.txt", scan_summary) {
            self.results.push(format!("⚠️ Scan history kaydedilemedi: {}", e));
        } else {
            self.results.push("💾 Scan sonuçları kaydedildi".to_string());
        }
        
        // JSON formatında da kaydet (reports için)
        if let Ok(json_data) = serde_json::to_string_pretty(&self.scan_results) {
            if let Err(e) = fs::write("last_scan_results.json", json_data) {
                self.results.push(format!("⚠️ JSON results kaydedilemedi: {}", e));
            }
        }
    }

    fn update_last_run_dates(&mut self) {
        use std::time::SystemTime;
        
        let now = SystemTime::now();
        
        // Çalıştırılan scanner'ların last_run tarihini güncelle
        let scanned_keys: Vec<String> = self.scan_results.iter()
            .map(|r| r.scanner_name.clone())
            .collect();
            
        for scanner in &mut self.scanners {
            // Scanner key'i exact match veya name contains olarak kontrol et
            if scanned_keys.iter().any(|key| {
                key == &scanner.scanner_key || 
                scanner.name.to_lowercase().contains(&key.to_lowercase()) ||
                key.to_lowercase().contains(&scanner.name.to_lowercase())
            }) {
                scanner.last_run = Some(now);
            }
        }
    }

    fn format_last_run(&self, last_run: &Option<SystemTime>) -> String {
        match last_run {
            Some(time) => {
                match time.elapsed() {
                    Ok(duration) => {
                        let secs = duration.as_secs();
                        if secs < 60 {
                            format!("{} saniye önce", secs)
                        } else if secs < 3600 {
                            format!("{} dakika önce", secs / 60)
                        } else if secs < 86400 {
                            format!("{} saat önce", secs / 3600)
                        } else {
                            format!("{} gün önce", secs / 86400)
                        }
                    }
                    Err(_) => "Geçersiz tarih".to_string()
                }
            }
            None => "Hiç çalıştırılmadı".to_string()
        }
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
            // Scan sonuçları varsa different help text göster
            if !self.scan_results.is_empty() {
                vec![
                    ("↑/↓", "Navigate"),
                    ("Enter", "Run scanner"),
                    ("A", "Run all"),
                    ("R", "View reports"),
                    ("C", "Clear results"),
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
    }

    fn tick(&mut self) {
        // Update scan progress and animations (non-blocking)
        if self.scanning {
            self.process_scan_step();
        }
    }
}

#[async_trait::async_trait(?Send)]
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
                KeyCode::Char('c') | KeyCode::Char('C') => {
                    self.clear_results();
                    Ok(Some(ScreenAction::SetStatus("Scan sonuçları temizlendi".to_string())))
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
                let last_run_text = self.format_last_run(&scanner.last_run);
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
                            &last_run_text,
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
        if !self.scan_results.is_empty() {
            // Scan sonuçları varsa bunları göster
            let total_findings = self.scan_results.iter().map(|r| r.findings.len()).sum::<usize>();
            let successful_scans = self.scan_results.iter().filter(|r| matches!(r.status, ScanStatus::Success)).count();
            
            let results_text = vec![
                Line::from(vec![
                    Span::styled("📊 Son Tarama Sonuçları:", theme.info_style()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("✅ Başarılı: ", theme.success_style()),
                    Span::styled(format!("{}", successful_scans), theme.list_item_style()),
                ]),
                Line::from(vec![
                    Span::styled("🔍 Toplam Bulgular: ", theme.warning_style()),
                    Span::styled(format!("{}", total_findings), theme.list_item_style()),
                ]),
                Line::from(""),
                Line::from(vec![
                    Span::styled("R", theme.accent_style()),
                    Span::styled(": Detaylı raporları görüntüle", theme.list_item_style()),
                ]),
                Line::from(vec![
                    Span::styled("C", theme.accent_style()),
                    Span::styled(": Sonuçları temizle", theme.list_item_style()),
                ]),
            ];

            let actions = Paragraph::new(results_text)
                .block(
                    Block::default()
                        .title(" 📊 Tarama Sonuçları ")
                        .title_style(theme.title_style())
                        .borders(Borders::ALL)
                        .border_style(theme.success_style())
                        .style(theme.box_style()),
                );

            frame.render_widget(actions, area);
        } else {
            // Normal hızlı işlemler menüsü
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
    }

    fn render_scanning_view(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),  // Progress (increased for better info)
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
        let layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(4),  // Info
                Constraint::Length(2),  // Progress bar
            ])
            .split(area);

        // Tarama bilgileri
        let elapsed_time = if let Some(start_time) = self.scan_start_time {
            format!("{:.1}s", start_time.elapsed().as_secs_f64())
        } else {
            "0s".to_string()
        };

        let progress_text = vec![
            Line::from(vec![
                Span::styled("🔄 İşlem: ", theme.info_style()),
                Span::styled(&self.current_operation, theme.list_item_style()),
            ]),
            Line::from(vec![
                Span::styled("📊 İlerleme: ", theme.info_style()),
                Span::styled(format!("{}/{} tamamlandı", self.completed_scanners, self.total_scanners), theme.warning_style()),
                Span::styled(format!("  ⏱️ Geçen süre: {}", elapsed_time), theme.muted_style()),
            ]),
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

        frame.render_widget(progress_info, layout[0]);

        // Progress bar ve sparkline
        let progress_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(70),  // Progress bar
                Constraint::Percentage(30),  // Sparkline
            ])
            .split(layout[1]);

        // Ana progress bar
        let gauge = Gauge::default()
            .block(Block::default())
            .gauge_style(theme.progress_style())
            .percent((self.progress * 100.0) as u16)
            .label(format!("{:.1}%", self.progress * 100.0));

        frame.render_widget(gauge, progress_layout[0]);

        // Progress animasyon sparkline
        let sparkline_data: Vec<u64> = self.progress_animation
            .iter()
            .map(|&x| (x * 100.0) as u64)
            .collect();

        let sparkline = Sparkline::default()
            .block(Block::default())
            .data(&sparkline_data)
            .style(theme.accent_style());

        frame.render_widget(sparkline, progress_layout[1]);
    }

    fn render_live_output(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let mut output_lines: Vec<Line> = Vec::new();

        // Eğer henüz sonuç yoksa progress mesajları göster
        if self.results.is_empty() && self.scanning {
            output_lines.push(Line::from(vec![
                Span::styled("🟡 ", theme.warning_style()),
                Span::styled("Tarama başlatılıyor...", theme.list_item_style()),
            ]));
            output_lines.push(Line::from(""));
            
            // Progress için scanner listesi
            for (i, scanner) in self.scanners.iter().enumerate() {
                if !scanner.enabled {
                    continue;
                }
                
                let status = if i < self.completed_scanners {
                    ("✅", theme.success_style())
                } else if Some(i) == self.current_scanner_index || (self.current_scanner_index.is_none() && i == self.completed_scanners) {
                    ("🟡", theme.warning_style())
                } else {
                    ("⏳", theme.muted_style())
                };
                
                output_lines.push(Line::from(vec![
                    Span::styled(format!("{} ", status.0), status.1),
                    Span::styled(&scanner.name, theme.list_item_style()),
                ]));
            }
        } else {
            // Gerçek sonuçları göster
            output_lines = self.results
                .iter()
                .map(|result| {
                    if result.starts_with("✅") {
                        Line::from(Span::styled(result, theme.success_style()))
                    } else if result.starts_with("⚠️") {
                        Line::from(Span::styled(result, theme.warning_style()))
                    } else if result.starts_with("❌") {
                        Line::from(Span::styled(result, theme.error_style()))
                    } else if result.starts_with("  🔴") {
                        Line::from(Span::styled(result, theme.error_style()))
                    } else if result.starts_with("  🟠") {
                        Line::from(Span::styled(result, theme.warning_style()))
                    } else if result.starts_with("  🟡") {
                        Line::from(Span::styled(result, theme.warning_style()))
                    } else {
                        Line::from(Span::styled(result, theme.list_item_style()))
                    }
                })
                .collect();
        }

        let title = if self.scanning {
            " 📝 Tarama Çıktısı (Canlı) "
        } else {
            " 📝 Tarama Sonuçları "
        };

        let output = Paragraph::new(output_lines)
            .block(
                Block::default()
                    .title(title)
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