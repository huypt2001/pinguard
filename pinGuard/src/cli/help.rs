//! Help system for the CLI

use crate::cli::display::{Display, Color};

/// Enhanced help system for PinGuard CLI
pub struct HelpSystem {
    display: Display,
}

impl HelpSystem {
    pub fn new() -> Self {
        Self {
            display: Display::new(),
        }
    }

    /// Show command examples
    pub fn show_examples(&self) {
        self.display.section_header("Usage Examples");
        
        let examples = vec![
            ("Basic Security Scan", "pinGuard scan"),
            ("Quick Package Scan", "pinGuard scan -m package"),
            ("Auto-fix Vulnerabilities", "pinGuard fix --auto"),
            ("Generate HTML Report", "pinGuard report -f html"),
            ("Interactive Mode", "pinGuard interactive"),
            ("Show Configuration", "pinGuard config show"),
            ("Update CVE Database", "pinGuard cve sync"),
            ("Schedule Daily Scan", "pinGuard schedule add daily '0 2 * * *'"),
        ];
        
        for (description, command) in examples {
            println!("  {} {}", 
                self.display.color_text("$", Color::Gray),
                self.display.color_text(command, Color::Cyan)
            );
            println!("    {}", description);
            println!();
        }
    }

    /// Show getting started guide
    pub fn show_getting_started(&self) {
        self.display.section_header("Getting Started with PinGuard");
        
        println!("1. {} Initialize configuration (optional):", 
            self.display.color_text("STEP 1:", Color::Green));
        println!("   pinGuard config init");
        println!();
        
        println!("2. {} Run your first security scan:", 
            self.display.color_text("STEP 2:", Color::Green));
        println!("   pinGuard scan");
        println!();
        
        println!("3. {} Generate a security report:", 
            self.display.color_text("STEP 3:", Color::Green));
        println!("   pinGuard report -f html");
        println!();
        
        println!("4. {} Fix found vulnerabilities:", 
            self.display.color_text("STEP 4:", Color::Green));
        println!("   pinGuard fix");
        println!();
        
        println!("5. {} Set up automated scans:", 
            self.display.color_text("STEP 5:", Color::Green));
        println!("   pinGuard schedule add daily '0 2 * * *'");
        println!();
    }

    /// Show troubleshooting guide
    pub fn show_troubleshooting(&self) {
        self.display.section_header("Troubleshooting");
        
        let issues = vec![
            (
                "Permission denied errors",
                vec![
                    "Run with sudo for system-level scans",
                    "Check file permissions for config/output directories",
                    "Ensure user is in required groups"
                ]
            ),
            (
                "Configuration file not found",
                vec![
                    "Run 'pinGuard config init' to create default config",
                    "Use -c flag to specify custom config file location",
                    "Check current directory for config.yaml"
                ]
            ),
            (
                "CVE database sync fails",
                vec![
                    "Check internet connection",
                    "Verify CVE API URL in configuration",
                    "Try manual sync with 'pinGuard cve sync --force'"
                ]
            ),
            (
                "Scan takes too long",
                vec![
                    "Use --quick flag for faster scans",
                    "Exclude modules with --exclude",
                    "Increase timeout with --timeout"
                ]
            ),
        ];
        
        for (issue, solutions) in issues {
            println!("{} {}", 
                self.display.color_text("Problem:", Color::Red),
                issue
            );
            
            for solution in solutions {
                println!("  • {}", solution);
            }
            println!();
        }
    }
}

impl Default for HelpSystem {
    fn default() -> Self {
        Self::new()
    }
}