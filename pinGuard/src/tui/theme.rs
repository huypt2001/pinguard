use ratatui::prelude::*;

/// Dark tema renk paleti - btop/bpytop tarzı
#[derive(Debug, Clone)]
pub struct Theme {
    pub bg: Color,
    pub fg: Color,
    pub border: Color,
    pub border_focused: Color,
    pub highlight: Color,
    pub accent: Color,
    pub success: Color,
    pub warning: Color,
    pub error: Color,
    pub info: Color,
    pub muted: Color,
    pub critical: Color,
}

impl Default for Theme {
    fn default() -> Self {
        Self {
            bg: Color::Rgb(26, 27, 38),           // Dark purple background
            fg: Color::Rgb(202, 211, 245),       // Light text
            border: Color::Rgb(68, 71, 90),      // Subtle border
            border_focused: Color::Rgb(137, 180, 250), // Blue focused border
            highlight: Color::Rgb(180, 190, 254), // Purple highlight
            accent: Color::Rgb(245, 194, 231),    // Pink accent
            success: Color::Rgb(166, 227, 161),   // Green
            warning: Color::Rgb(249, 226, 175),   // Yellow
            error: Color::Rgb(243, 139, 168),     // Red
            info: Color::Rgb(137, 220, 235),      // Cyan
            muted: Color::Rgb(108, 112, 134),     // Muted text
            critical: Color::Rgb(255, 99, 71),    // Bright red for critical issues
        }
    }
}

impl Theme {
    /// Box style'ları
    pub fn box_style(&self) -> Style {
        Style::default()
            .bg(self.bg)
            .fg(self.fg)
    }

    pub fn focused_box_style(&self) -> Style {
        Style::default()
            .bg(self.bg)
            .fg(self.fg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn border_style(&self) -> Style {
        Style::default().fg(self.border)
    }

    pub fn focused_border_style(&self) -> Style {
        Style::default().fg(self.border_focused)
    }

    /// Liste item'ları için style'lar
    pub fn list_item_style(&self) -> Style {
        Style::default()
            .bg(self.bg)
            .fg(self.fg)
    }

    pub fn selected_item_style(&self) -> Style {
        Style::default()
            .bg(self.highlight)
            .fg(self.bg)
            .add_modifier(Modifier::BOLD)
    }

    /// Durum indicator'ları için style'lar
    pub fn success_style(&self) -> Style {
        Style::default().fg(self.success).add_modifier(Modifier::BOLD)
    }

    pub fn warning_style(&self) -> Style {
        Style::default().fg(self.warning).add_modifier(Modifier::BOLD)
    }

    pub fn error_style(&self) -> Style {
        Style::default().fg(self.error).add_modifier(Modifier::BOLD)
    }

    pub fn critical_style(&self) -> Style {
        Style::default().fg(self.critical).add_modifier(Modifier::BOLD)
    }

    pub fn info_style(&self) -> Style {
        Style::default().fg(self.info)
    }

    pub fn muted_style(&self) -> Style {
        Style::default().fg(self.muted)
    }

    /// Progress bar style'ları
    pub fn progress_style(&self) -> Style {
        Style::default().fg(self.accent)
    }

    pub fn progress_bg_style(&self) -> Style {
        Style::default().bg(self.muted)
    }

    /// Header/Title style'ları
    pub fn header_style(&self) -> Style {
        Style::default()
            .fg(self.accent)
            .add_modifier(Modifier::BOLD)
    }

    pub fn title_style(&self) -> Style {
        Style::default()
            .fg(self.border_focused)
            .add_modifier(Modifier::BOLD)
    }

    /// Severity göstergesi için renk döndür
    pub fn severity_color(&self, severity: &str) -> Color {
        match severity.to_lowercase().as_str() {
            "critical" => self.critical,
            "high" => self.error,
            "medium" => self.warning,
            "low" => self.info,
            _ => self.muted,
        }
    }

    /// Severity göstergisi için style döndür
    pub fn severity_style(&self, severity: &str) -> Style {
        Style::default()
            .fg(self.severity_color(severity))
            .add_modifier(Modifier::BOLD)
    }

    /// Accent style (vurgu için)
    pub fn accent_style(&self) -> Style {
        Style::default().fg(self.accent).add_modifier(Modifier::BOLD)
    }
}

/// Risk seviyesine göre renk döndüren yardımcı fonksiyon
pub fn risk_color(theme: &Theme, risk: u32) -> Color {
    match risk {
        0..=3 => theme.success,      // Düşük risk - yeşil
        4..=6 => theme.warning,      // Orta risk - sarı  
        7..=8 => theme.error,        // Yüksek risk - kırmızı
        9..=10 => theme.critical,    // Kritik risk - parlak kırmızı
        _ => theme.muted,
    }
}

/// Durum göstergesi için emoji/sembol döndüren yardımcı fonksiyon
pub fn status_symbol(status: &str) -> &str {
    match status.to_lowercase().as_str() {
        "success" | "ok" | "pass" => "✓",
        "warning" | "warn" => "⚠",
        "error" | "fail" | "failed" => "✗",
        "info" => "ⓘ",
        "running" | "progress" => "⟳",
        "pending" => "⏳",
        _ => "•",
    }
}