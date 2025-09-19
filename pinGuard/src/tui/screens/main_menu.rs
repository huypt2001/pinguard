use crossterm::event::{KeyCode, KeyEvent};
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};

use crate::core::errors::PinGuardError;
use crate::tui::theme::Theme;
use super::{Screen, AsyncKeyHandler, ScreenAction, ScreenType};

/// Ana menü öğeleri
#[derive(Debug, Clone)]
struct MenuItem {
    pub title: String,
    pub description: String,
    pub action: MenuAction,
    pub enabled: bool,
}

#[derive(Debug, Clone)]
enum MenuAction {
    OpenScanner,
    OpenFixer,
    OpenReports,
    OpenSettings,
    Quit,
}

/// Ana menü ekranı
pub struct MainMenuScreen {
    items: Vec<MenuItem>,
    list_state: ListState,
    system_info: SystemInfo,
}

#[derive(Debug)]
struct SystemInfo {
    hostname: String,
    os_info: String,
    uptime: String,
    last_scan: Option<String>,
    vulnerabilities_found: u32,
    critical_issues: u32,
}

impl MainMenuScreen {
    pub fn new() -> Self {
        let items = vec![
            MenuItem {
                title: "🔍 Security Scan".to_string(),
                description: "Sistem güvenlik taraması başlat".to_string(),
                action: MenuAction::OpenScanner,
                enabled: true,
            },
            MenuItem {
                title: "🛠️  Security Fix".to_string(),
                description: "Güvenlik açıklarını düzelt".to_string(),
                action: MenuAction::OpenFixer,
                enabled: true,
            },
            MenuItem {
                title: "📊 Reports".to_string(),
                description: "Güvenlik raporlarını görüntüle".to_string(),
                action: MenuAction::OpenReports,
                enabled: true,
            },
            MenuItem {
                title: "⚙️  Settings".to_string(),
                description: "Ayarları düzenle".to_string(),
                action: MenuAction::OpenSettings,
                enabled: true,
            },
            MenuItem {
                title: "🚪 Exit".to_string(),
                description: "Uygulamadan çık".to_string(),
                action: MenuAction::Quit,
                enabled: true,
            },
        ];

        let mut list_state = ListState::default();
        list_state.select(Some(0));

        let system_info = SystemInfo::fetch();

        Self {
            items,
            list_state,
            system_info,
        }
    }

    fn next(&mut self) {
        let i = match self.list_state.selected() {
            Some(i) => {
                if i >= self.items.len() - 1 {
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
                    self.items.len() - 1
                } else {
                    i - 1
                }
            }
            None => 0,
        };
        self.list_state.select(Some(i));
    }

    fn select_current(&self) -> Option<ScreenAction> {
        if let Some(i) = self.list_state.selected() {
            if let Some(item) = self.items.get(i) {
                if item.enabled {
                    match &item.action {
                        MenuAction::OpenScanner => Some(ScreenAction::SwitchScreen(ScreenType::Scanner)),
                        MenuAction::OpenFixer => Some(ScreenAction::SwitchScreen(ScreenType::Fixer)),
                        MenuAction::OpenReports => Some(ScreenAction::SwitchScreen(ScreenType::Reports)),
                        MenuAction::OpenSettings => Some(ScreenAction::SwitchScreen(ScreenType::Settings)),
                        MenuAction::Quit => Some(ScreenAction::Quit),
                    }
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

impl Screen for MainMenuScreen {
    fn title(&self) -> &str {
        "Ana Menü"
    }

    fn render(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        // Ana layout: sol taraf menü, sağ taraf sistem bilgisi
        let main_layout = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);

        // Sol taraf: Menü
        self.render_menu(frame, main_layout[0], theme);

        // Sağ taraf: Sistem bilgisi ve son durum
        self.render_system_info(frame, main_layout[1], theme);
    }

    fn help_text(&self) -> Vec<(&str, &str)> {
        vec![
            ("↑/↓", "Navigate"),
            ("Enter", "Select"),
            ("1-4", "Quick access"),
            ("q", "Quit"),
        ]
    }

    fn tick(&mut self) {
        // Sistem bilgilerini periyodik olarak güncelle
        self.system_info = SystemInfo::fetch();
    }
}

#[async_trait::async_trait]
impl AsyncKeyHandler for MainMenuScreen {
    async fn handle_key_events(&mut self, key_event: KeyEvent) 
        -> Result<Option<ScreenAction>, PinGuardError> {
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
                Ok(self.select_current())
            }
            KeyCode::Char('1') => {
                Ok(Some(ScreenAction::SwitchScreen(ScreenType::Scanner)))
            }
            KeyCode::Char('2') => {
                Ok(Some(ScreenAction::SwitchScreen(ScreenType::Fixer)))
            }
            KeyCode::Char('3') => {
                Ok(Some(ScreenAction::SwitchScreen(ScreenType::Reports)))
            }
            KeyCode::Char('4') => {
                Ok(Some(ScreenAction::SwitchScreen(ScreenType::Settings)))
            }
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                Ok(Some(ScreenAction::Quit))
            }
            _ => Ok(None),
        }
    }
}

impl MainMenuScreen {
    fn render_menu(&mut self, frame: &mut Frame, area: Rect, theme: &Theme) {
        // Menü items'ı oluştur
        let items: Vec<ListItem> = self
            .items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let style = if Some(i) == self.list_state.selected() {
                    theme.selected_item_style()
                } else if item.enabled {
                    theme.list_item_style()
                } else {
                    theme.muted_style()
                };

                let status = if item.enabled { "●" } else { "○" };
                
                let content = vec![
                    Line::from(vec![
                        Span::styled(format!(" {} ", status), theme.accent_style()),
                        Span::styled(&item.title, style),
                    ]),
                    Line::from(vec![
                        Span::styled("   ", style),
                        Span::styled(&item.description, theme.muted_style()),
                    ]),
                ];

                ListItem::new(content)
            })
            .collect();

        let block = Block::default()
            .title(" 🛡️ PinGuard Ana Menü ")
            .title_style(theme.title_style())
            .borders(Borders::ALL)
            .border_style(theme.focused_border_style())
            .style(theme.box_style());

        let list = List::new(items)
            .block(block)
            .highlight_style(theme.selected_item_style());

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_system_info(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let info_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(8),  // Sistem bilgisi
                Constraint::Min(0),     // Güvenlik durumu
            ])
            .split(area);

        // Sistem bilgisi
        self.render_system_details(frame, info_layout[0], theme);

        // Güvenlik durumu
        self.render_security_status(frame, info_layout[1], theme);
    }

    fn render_system_details(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let system_text = vec![
            Line::from(vec![
                Span::styled("🖥️  Host: ", theme.info_style()),
                Span::styled(&self.system_info.hostname, theme.list_item_style()),
            ]),
            Line::from(vec![
                Span::styled("🐧 OS: ", theme.info_style()),
                Span::styled(&self.system_info.os_info, theme.list_item_style()),
            ]),
            Line::from(vec![
                Span::styled("⏰ Uptime: ", theme.info_style()),
                Span::styled(&self.system_info.uptime, theme.list_item_style()),
            ]),
            Line::from(vec![
                Span::styled("🔍 Last Scan: ", theme.info_style()),
                Span::styled(
                    self.system_info.last_scan.as_deref().unwrap_or("Never"),
                    if self.system_info.last_scan.is_some() {
                        theme.success_style()
                    } else {
                        theme.warning_style()
                    }
                ),
            ]),
        ];

        let system_info = Paragraph::new(system_text)
            .block(
                Block::default()
                    .title(" 📋 Sistem Bilgisi ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(theme.border_style())
                    .style(theme.box_style()),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(system_info, area);
    }

    fn render_security_status(&self, frame: &mut Frame, area: Rect, theme: &Theme) {
        let status_color = if self.system_info.critical_issues > 0 {
            theme.critical_style()
        } else if self.system_info.vulnerabilities_found > 0 {
            theme.warning_style()
        } else {
            theme.success_style()
        };

        let status_text = if self.system_info.critical_issues > 0 {
            "🔴 CRITICAL"
        } else if self.system_info.vulnerabilities_found > 0 {
            "🟡 WARNING"
        } else {
            "🟢 SECURE"
        };

        let security_text = vec![
            Line::from(vec![
                Span::styled("🔒 Güvenlik Durumu: ", theme.info_style()),
                Span::styled(status_text, status_color),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("🐛 Toplam Açık: ", theme.info_style()),
                Span::styled(
                    self.system_info.vulnerabilities_found.to_string(),
                    if self.system_info.vulnerabilities_found > 0 {
                        theme.warning_style()
                    } else {
                        theme.success_style()
                    }
                ),
            ]),
            Line::from(vec![
                Span::styled("⚠️  Kritik Açık: ", theme.info_style()),
                Span::styled(
                    self.system_info.critical_issues.to_string(),
                    if self.system_info.critical_issues > 0 {
                        theme.critical_style()
                    } else {
                        theme.success_style()
                    }
                ),
            ]),
        ];

        let security_status = Paragraph::new(security_text)
            .block(
                Block::default()
                    .title(" 🛡️ Güvenlik Durumu ")
                    .title_style(theme.title_style())
                    .borders(Borders::ALL)
                    .border_style(if self.system_info.critical_issues > 0 {
                        theme.error_style()
                    } else if self.system_info.vulnerabilities_found > 0 {
                        theme.warning_style()
                    } else {
                        theme.success_style()
                    })
                    .style(theme.box_style()),
            )
            .wrap(ratatui::widgets::Wrap { trim: true });

        frame.render_widget(security_status, area);
    }
}

impl SystemInfo {
    fn fetch() -> Self {
        use std::process::Command;

        // Hostname
        let hostname = Command::new("hostname")
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .unwrap_or_else(|_| "Unknown".to_string());

        // OS info
        let os_info = std::fs::read_to_string("/etc/os-release")
            .and_then(|content| {
                for line in content.lines() {
                    if line.starts_with("PRETTY_NAME=") {
                        let name = line.split('=').nth(1).unwrap_or("");
                        return Ok(name.trim_matches('"').to_string());
                    }
                }
                Ok("Linux".to_string())
            })
            .unwrap_or_else(|_| "Unknown Linux".to_string());

        // Uptime
        let uptime = std::fs::read_to_string("/proc/uptime")
            .and_then(|content| {
                let seconds: f64 = content.split_whitespace()
                    .next()
                    .unwrap_or("0")
                    .parse()
                    .unwrap_or(0.0);
                
                let days = (seconds / 86400.0) as u32;
                let hours = ((seconds % 86400.0) / 3600.0) as u32;
                let minutes = ((seconds % 3600.0) / 60.0) as u32;
                
                Ok(format!("{}d {}h {}m", days, hours, minutes))
            })
            .unwrap_or_else(|_| "Unknown".to_string());

        // Mock data for now - bu bilgiler gerçek scan verilerinden gelecek
        Self {
            hostname,
            os_info,
            uptime,
            last_scan: None, // TODO: Database'den al
            vulnerabilities_found: 0, // TODO: Database'den al
            critical_issues: 0, // TODO: Database'den al
        }
    }
}