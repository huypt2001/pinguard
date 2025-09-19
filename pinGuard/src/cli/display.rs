//! Display utilities for enhanced CLI output
//! Provides colored output, ASCII art, progress indicators, and formatting

use std::io::{self, Write};

/// Display utility for enhanced CLI output
pub struct Display {
    pub use_colors: bool,
}

impl Display {
    /// Create a new display instance
    pub fn new() -> Self {
        Self {
            use_colors: supports_color(),
        }
    }

    /// Show the PinGuard ASCII logo
    pub fn show_logo(&self) {
        let logo = r#"
 _____________       _____________  ________________________ 
___  __ \__(_)________  ____/_  / / /__    |__  __ \__  __ \
__  /_/ /_  /__  __ \  / __ _  / / /__  /| |_  /_/ /_  / / /
_  ____/_  / _  / / / /_/ / / /_/ / _  ___ |  _, _/_  /_/ / 
/_/     /_/  /_/ /_/\____/  \____/  /_/  |_/_/ |_| /_____/  
                                                            
"#;

        if self.use_colors {
            println!("{}", self.color_text(logo, Color::Cyan));
        } else {
            println!("{}", logo);
        }
        
        println!("{}", self.color_text("Linux Vulnerability Scanner & Remediator", Color::Blue));
        println!("{}", self.color_text(&format!("Version {}", env!("CARGO_PKG_VERSION")), Color::Gray));
        println!();
    }

    /// Show quick help information
    pub fn show_quick_help(&self) {
        println!("{}", self.color_text("Quick Start:", Color::Green));
        println!("  {} {}  {}", 
            self.color_text("pinGuard", Color::Cyan),
            self.color_text("scan", Color::Yellow),
            "- Perform a security scan"
        );
        println!("  {} {}   {}", 
            self.color_text("pinGuard", Color::Cyan),
            self.color_text("fix", Color::Yellow),
            "- Fix found vulnerabilities"
        );
        println!("  {} {} {}", 
            self.color_text("pinGuard", Color::Cyan),
            self.color_text("report", Color::Yellow),
            "- Generate security report"
        );
        println!("  {} {}  {}", 
            self.color_text("pinGuard", Color::Cyan),
            self.color_text("--help", Color::Yellow),
            "- Show all available commands"
        );
        println!();
    }

    /// Display success message
    pub fn success(&self, message: &str) {
        if self.use_colors {
            println!("{} {}", self.color_text("✓", Color::Green), message);
        } else {
            println!("[SUCCESS] {}", message);
        }
    }

    /// Display error message
    pub fn error(&self, message: &str) {
        if self.use_colors {
            eprintln!("{} {}", self.color_text("✗", Color::Red), message);
        } else {
            eprintln!("[ERROR] {}", message);
        }
    }

    /// Display warning message
    pub fn warning(&self, message: &str) {
        if self.use_colors {
            println!("{} {}", self.color_text("⚠", Color::Yellow), message);
        } else {
            println!("[WARNING] {}", message);
        }
    }

    /// Display info message
    pub fn info(&self, message: &str) {
        if self.use_colors {
            println!("{} {}", self.color_text("ℹ", Color::Blue), message);
        } else {
            println!("[INFO] {}", message);
        }
    }

    /// Display a section header
    pub fn section_header(&self, title: &str) {
        println!();
        if self.use_colors {
            println!("{}", self.color_text(&format!("▶ {}", title), Color::Cyan));
        } else {
            println!(">> {}", title);
        }
        println!("{}", "─".repeat(title.len() + 3));
    }

    /// Display a progress bar
    pub fn progress_bar(&self, current: usize, total: usize, message: &str) {
        let percentage = (current as f64 / total as f64 * 100.0) as usize;
        let filled = percentage / 2; // 50 chars max
        let empty = 50 - filled;

        if self.use_colors {
            print!("\r{} [{}{}] {}% - {}", 
                self.color_text("⏳", Color::Yellow),
                "█".repeat(filled),
                "░".repeat(empty),
                percentage,
                message
            );
        } else {
            print!("\r[{}{}] {}% - {}", 
                "#".repeat(filled),
                "-".repeat(empty),
                percentage,
                message
            );
        }
        io::stdout().flush().unwrap();

        if current == total {
            println!(); // New line when complete
        }
    }

    /// Display a table with headers and rows
    pub fn table(&self, headers: &[&str], rows: &[Vec<String>]) {
        if rows.is_empty() {
            self.warning("No data to display");
            return;
        }

        // Calculate column widths
        let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();
        for row in rows {
            for (i, cell) in row.iter().enumerate() {
                if i < widths.len() {
                    widths[i] = widths[i].max(cell.len());
                }
            }
        }

        // Print header
        print!("│");
        for (i, header) in headers.iter().enumerate() {
            print!(" {:<width$} │", header, width = widths[i]);
        }
        println!();

        // Print separator
        print!("├");
        for width in &widths {
            print!("{}┼", "─".repeat(width + 2));
        }
        println!("┤");

        // Print rows
        for row in rows {
            print!("│");
            for (i, cell) in row.iter().enumerate() {
                let width = if i < widths.len() { widths[i] } else { 0 };
                print!(" {:<width$} │", cell, width = width);
            }
            println!();
        }
    }

    /// Display a key-value list
    pub fn key_value_list(&self, items: &[(&str, &str)]) {
        let max_key_width = items.iter().map(|(k, _)| k.len()).max().unwrap_or(0);
        
        for (key, value) in items {
            if self.use_colors {
                println!("  {:<width$} : {}", 
                    self.color_text(key, Color::Cyan),
                    value,
                    width = max_key_width
                );
            } else {
                println!("  {:<width$} : {}", key, value, width = max_key_width);
            }
        }
    }

    /// Ask for user confirmation
    pub fn confirm(&self, message: &str) -> bool {
        if self.use_colors {
            print!("{} {} [y/N]: ", 
                self.color_text("?", Color::Yellow),
                message
            );
        } else {
            print!("{} [y/N]: ", message);
        }
        
        io::stdout().flush().unwrap();
        
        let mut input = String::new();
        io::stdin().read_line(&mut input).unwrap();
        
        matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
    }

    /// Color text if colors are supported
    pub fn color_text(&self, text: &str, color: Color) -> String {
        if self.use_colors {
            match color {
                Color::Red => format!("\x1b[31m{}\x1b[0m", text),
                Color::Green => format!("\x1b[32m{}\x1b[0m", text),
                Color::Yellow => format!("\x1b[33m{}\x1b[0m", text),
                Color::Blue => format!("\x1b[34m{}\x1b[0m", text),
                Color::Magenta => format!("\x1b[35m{}\x1b[0m", text),
                Color::Cyan => format!("\x1b[36m{}\x1b[0m", text),
                Color::Gray => format!("\x1b[90m{}\x1b[0m", text),
                Color::Bold => format!("\x1b[1m{}\x1b[0m", text),
            }
        } else {
            text.to_string()
        }
    }

    /// Display scan results summary
    pub fn scan_summary(&self, findings: usize, critical: usize, high: usize, medium: usize, low: usize) {
        self.section_header("Scan Results Summary");
        
        let findings_str = findings.to_string();
        let critical_str = critical.to_string();
        let high_str = high.to_string();
        let medium_str = medium.to_string();
        let low_str = low.to_string();
        
        let items = vec![
            ("Total Findings", findings_str.as_str()),
            ("Critical", critical_str.as_str()),
            ("High", high_str.as_str()),
            ("Medium", medium_str.as_str()),
            ("Low", low_str.as_str()),
        ];
        
        self.key_value_list(&items);
        
        if critical > 0 {
            self.error(&format!("⚠ {} critical vulnerabilities found!", critical));
        } else if high > 0 {
            self.warning(&format!("{} high-severity vulnerabilities found", high));
        } else {
            self.success("No critical or high-severity vulnerabilities found");
        }
    }
}

impl Default for Display {
    fn default() -> Self {
        Self::new()
    }
}

/// Color enum for terminal output
pub enum Color {
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    Gray,
    Bold,
}

/// Check if the terminal supports colors
fn supports_color() -> bool {
    // Check if we're in a terminal and TERM env var is set
    if let Ok(term) = std::env::var("TERM") {
        !term.is_empty() && term != "dumb" && atty::is(atty::Stream::Stdout)
    } else {
        false
    }
}