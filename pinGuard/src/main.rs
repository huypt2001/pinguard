use clap::{Command, Arg, ArgMatches};
use libc;
use tracing::{info, warn, error, Level};
use tracing_subscriber::FmtSubscriber;

mod core;
mod scanners;
mod fixers;
mod report;
mod database;
mod cve;
mod scheduler;

use database::DatabaseManager;
use cve::CveManager;
use scheduler::Scheduler;

fn main() {
    // Set up the logging subscriber
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();

    tracing::subscriber::set_global_default(subscriber).expect("setting default subscriber failed");

    info!("🛡️  PinGuard - Linux Vulnerability Scanner & Remediator başlatılıyor...");

    // Check for root privileges (temporarily disabled for testing)
    // if unsafe { libc::geteuid() } != 0 {
    //     error!("❌ Hata: Bu program root yetkileri ile çalıştırılmalıdır.");
    //     eprintln!("Lütfen programı 'sudo' ile çalıştırın.");
    //     std::process::exit(1);
    // }

    let matches = build_cli().get_matches();
    
    // Config dosyasını yükle
    let config_path = matches.get_one::<String>("config").map(|s| s.as_str()).unwrap_or("config.yaml");
    let config = match core::config::Config::load_from_file(config_path) {
        Ok(config) => {
            info!("✅ Konfigurasyon dosyası başarıyla yüklendi: {}", config_path);
            config
        },
        Err(e) => {
            warn!("⚠️  Config dosyası yüklenemedi ({}), varsayılan ayarlar kullanılıyor", e);
            core::config::Config::default()
        },
    };

    // Alt komutları işle
    match matches.subcommand() {
        Some(("scan", sub_matches)) => handle_scan_command(sub_matches, &config),
        Some(("fix", sub_matches)) => handle_fix_command(sub_matches, &config),
        Some(("report", sub_matches)) => handle_report_command(sub_matches, &config),
        Some(("config", sub_matches)) => handle_config_command(sub_matches, &config),
        Some(("database", sub_matches)) => handle_database_command(sub_matches, &config),
        Some(("cve", sub_matches)) => handle_cve_command(sub_matches, &config),
        Some(("schedule", sub_matches)) => handle_schedule_command(sub_matches, &config),
        Some(("run-scheduled-scan", sub_matches)) => handle_run_scheduled_scan(sub_matches, &config),
        _ => {
            info!("ℹ️  Kullanılabilir komutlar için 'pinGuard --help' çalıştırın");
        }
    }
}

fn build_cli() -> Command {
    Command::new("pinGuard")
        .version("0.1.0")
        .author("PinGuard Team")
        .about("🛡️  Linux-first Vulnerability Scanner & Remediator")
        .long_about("PinGuard, Linux sistemlerde güvenlik açıklarını tarar, raporlar ve düzeltir.")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Özel config dosyası belirtir")
                .value_parser(clap::value_parser!(String)),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .action(clap::ArgAction::SetTrue)
                .help("Detaylı çıktı gösterir"),
        )
        .subcommand(
            Command::new("scan")
                .about("Sistem güvenlik taraması yapar")
                .arg(
                    Arg::new("module")
                        .short('m')
                        .long("module")
                        .value_name("MODULE")
                        .help("Belirli bir modülü tarar (package, kernel, service, network)")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("FILE")
                        .help("Çıktı dosyası")
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            Command::new("fix")
                .about("Bulunan güvenlik açıklarını düzeltir")
                .arg(
                    Arg::new("auto")
                        .long("auto")
                        .action(clap::ArgAction::SetTrue)
                        .help("Otomatik düzeltme (onay istemez)"),
                )
                .arg(
                    Arg::new("module")
                        .short('m')
                        .long("module")
                        .value_name("MODULE")
                        .help("Belirli bir modülü düzeltir")
                        .value_parser(clap::value_parser!(String)),
                ),
        )
        .subcommand(
            Command::new("report")
                .about("Tarama sonuçlarından rapor oluşturur")
                .arg(
                    Arg::new("format")
                        .short('f')
                        .long("format")
                        .value_name("FORMAT")
                        .help("Rapor formatı (json, html, pdf, all)")
                        .value_parser(clap::value_parser!(String))
                        .default_value("json"),
                )
                .arg(
                    Arg::new("output")
                        .short('o')
                        .long("output")
                        .value_name("FILE")
                        .help("Çıktı dosyası veya dizini")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("input")
                        .short('i')
                        .long("input")
                        .value_name("FILE")
                        .help("Girdi tarama dosyası (JSON format)")
                        .value_parser(clap::value_parser!(String)),
                )
                .arg(
                    Arg::new("scan")
                        .long("scan")
                        .action(clap::ArgAction::SetTrue)
                        .help("Önce yeni tarama yap, sonra rapor oluştur"),
                )
                .arg(
                    Arg::new("summary")
                        .long("summary")
                        .action(clap::ArgAction::SetTrue)
                        .help("Sadece özet raporu konsola yazdır"),
                ),
        )
        .subcommand(
            Command::new("config")
                .about("Konfigürasyon yönetimi")
                .arg(
                    Arg::new("show")
                        .long("show")
                        .action(clap::ArgAction::SetTrue)
                        .help("Mevcut konfigürasyonu gösterir"),
                )
                .arg(
                    Arg::new("init")
                        .long("init")
                        .action(clap::ArgAction::SetTrue)
                        .help("Varsayılan config dosyası oluşturur"),
                ),
        )
        .subcommand(
            Command::new("database")
                .about("💾 Veritabanı yönetimi")
                .subcommand(
                    Command::new("init")
                        .about("Veritabanını başlat ve tabloları oluştur")
                )
                .subcommand(
                    Command::new("migrate")
                        .about("Veritabanı migration'larını çalıştır")
                )
                .subcommand(
                    Command::new("health")
                        .about("Veritabanı sağlık kontrolü yap")
                )
                .subcommand(
                    Command::new("stats")
                        .about("Veritabanı istatistiklerini göster")
                )
                .subcommand(
                    Command::new("cleanup")
                        .about("Eski verileri temizle")
                        .arg(
                            Arg::new("days")
                                .short('d')
                                .long("days")
                                .value_name("DAYS")
                                .help("Kaç günden eski veriler silinsin")
                                .value_parser(clap::value_parser!(u32))
                                .default_value("30"),
                        )
                )
        )
        .subcommand(
            Command::new("cve")
                .about("🔍 CVE veritabanı yönetimi")
                .subcommand(
                    Command::new("sync")
                        .about("NVD'den son CVE'leri senkronize et")
                        .arg(
                            Arg::new("days")
                                .short('d')
                                .long("days")
                                .value_name("DAYS")
                                .help("Son kaç günün CVE'leri")
                                .value_parser(clap::value_parser!(u32))
                                .default_value("7"),
                        )
                )
                .subcommand(
                    Command::new("search")
                        .about("CVE ara")
                        .arg(
                            Arg::new("query")
                                .help("Arama terimi (CVE ID, paket adı, keyword)")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("limit")
                                .short('l')
                                .long("limit")
                                .value_name("LIMIT")
                                .help("Maksimum sonuç sayısı")
                                .value_parser(clap::value_parser!(usize))
                                .default_value("10"),
                        )
                )
                .subcommand(
                    Command::new("get")
                        .about("Belirli CVE'yi detaylarıyla getir")
                        .arg(
                            Arg::new("cve_id")
                                .help("CVE ID (örn: CVE-2023-1234)")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        )
                )
                .subcommand(
                    Command::new("health")
                        .about("CVE manager sağlık kontrolü")
                )
                .subcommand(
                    Command::new("cache")
                        .about("CVE cache yönetimi")
                        .subcommand(
                            Command::new("stats")
                                .about("Cache istatistikleri")
                        )
                        .subcommand(
                            Command::new("cleanup")
                                .about("Expire olmuş cache temizle")
                        )
                        .subcommand(
                            Command::new("refresh")
                                .about("Cache'i yenile")
                        )
                )
        )
        .subcommand(
            Command::new("schedule")
                .about("⏰ Otomatik tarama planlayıcısı")
                .subcommand(
                    Command::new("enable")
                        .about("Planlı tarama etkinleştir")
                        .arg(
                            Arg::new("name")
                                .help("Schedule adı")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("schedule")
                                .help("Cron ifadesi (örn: '0 2 * * *')")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("description")
                                .short('d')
                                .long("description")
                                .value_name("DESC")
                                .help("Schedule açıklaması")
                                .value_parser(clap::value_parser!(String)),
                        )
                        .arg(
                            Arg::new("type")
                                .short('t')
                                .long("type")
                                .value_name("TYPE")
                                .help("Tarama türü (full, quick, security)")
                                .value_parser(clap::value_parser!(String))
                                .default_value("full"),
                        )
                )
                .subcommand(
                    Command::new("disable")
                        .about("Planlı tarama devre dışı bırak")
                        .arg(
                            Arg::new("name")
                                .help("Schedule adı")
                                .required(true)
                                .value_parser(clap::value_parser!(String)),
                        )
                )
                .subcommand(
                    Command::new("list")
                        .about("Aktif planlı taramaları listele")
                )
                .subcommand(
                    Command::new("status")
                        .about("Schedule durumunu göster")
                        .arg(
                            Arg::new("name")
                                .help("Schedule adı (tümü için boş bırak)")
                                .value_parser(clap::value_parser!(String)),
                        )
                )
                .subcommand(
                    Command::new("presets")
                        .about("Hazır schedule şablonlarını yükle")
                )
        )
        .subcommand(
            Command::new("run-scheduled-scan")
                .about("🤖 Planlı tarama çalıştır (systemd tarafından kullanılır)")
                .arg(
                    Arg::new("schedule_name")
                        .help("Schedule adı")
                        .required(true)
                        .value_parser(clap::value_parser!(String)),
                )
                .hide(true) // Bu komut kullanıcıya gösterilmez
        )
}

fn handle_scan_command(matches: &ArgMatches, config: &core::config::Config) {
    info!("🔍 Tarama başlatılıyor...");
    
    let scanner_manager = scanners::manager::ScannerManager::new();
    
    if let Some(module) = matches.get_one::<String>("module") {
        info!("📦 Belirli tarama modülü: {}", module);
        
        match scanner_manager.run_specific_scan(module, config) {
            Ok(result) => {
                info!("✅ {} tamamlandı: {} bulgu", module, result.findings.len());
                
                // JSON çıktısı
                if let Some(output_file) = matches.get_one::<String>("output") {
                    match std::fs::write(output_file, serde_json::to_string_pretty(&result).unwrap()) {
                        Ok(_) => info!("� Sonuçlar şuraya kaydedildi: {}", output_file),
                        Err(e) => error!("❌ Dosya yazma hatası: {}", e),
                    }
                } else {
                    // Console'a özet yazdır
                    print_scan_summary(&result);
                }
            }
            Err(e) => {
                error!("❌ Tarama başarısız: {}", e);
            }
        }
    } else {
        info!("�🔍 Tüm aktif modüller taranacak: {:?}", config.scanner.enabled_modules);
        
        let results = scanner_manager.run_all_scans(config);
        let summary = scanner_manager.generate_summary(&results);
        
        info!("🎯 Tarama özeti:");
        info!("   📊 Toplam tarama: {}", summary.total_scans);
        info!("   ✅ Başarılı: {}", summary.successful_scans);
        info!("   ⚠️  Uyarı: {}", summary.warning_scans);
        info!("   ❌ Başarısız: {}", summary.failed_scans);
        info!("   🔍 Toplam bulgu: {}", summary.total_findings);
        info!("   🚨 Kritik: {}", summary.critical_issues);
        info!("   🔥 Yüksek: {}", summary.high_issues);
        info!("   ⚠️  Orta: {}", summary.medium_issues);
        info!("   ℹ️  Düşük: {}", summary.low_issues);
        info!("   📈 Güvenlik puanı: {}/100", summary.get_security_score());
        info!("   🎯 Risk seviyesi: {}", summary.get_risk_level());
        
        // JSON çıktısı
        if let Some(output_file) = matches.get_one::<String>("output") {
            match scanner_manager.results_to_json(&results) {
                Ok(json) => {
                    match std::fs::write(output_file, json) {
                        Ok(_) => info!("📄 Tüm sonuçlar şuraya kaydedildi: {}", output_file),
                        Err(e) => error!("❌ Dosya yazma hatası: {}", e),
                    }
                }
                Err(e) => error!("❌ JSON oluşturma hatası: {}", e),
            }
        }
    }
}

fn print_scan_summary(result: &scanners::ScanResult) {
    println!("\n🔍 {} Tarama Sonucu", result.scanner_name);
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!("📅 Tarama zamanı: {}", result.scan_time);
    println!("⏱️  Süre: {} ms", result.metadata.duration_ms);
    println!("📊 Taranan öğe: {}", result.metadata.items_scanned);
    println!("🔍 Toplam bulgu: {}", result.findings.len());
    
    if !result.findings.is_empty() {
        println!("\n📋 Bulgular:");
        for (i, finding) in result.findings.iter().enumerate() {
            let severity_icon = match finding.severity {
                scanners::Severity::Critical => "🚨",
                scanners::Severity::High => "🔥",
                scanners::Severity::Medium => "⚠️",
                scanners::Severity::Low => "ℹ️",
                scanners::Severity::Info => "💡",
            };
            println!("{}. {} {} - {}", i + 1, severity_icon, finding.title, finding.description);
        }
    } else {
        println!("✅ Güvenlik açığı bulunamadı!");
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

fn handle_fix_command(matches: &ArgMatches, config: &core::config::Config) {
    info!("🔧 Düzeltme başlatılıyor...");
    
    let auto_fix = matches.get_flag("auto");
    if auto_fix {
        warn!("⚡ Otomatik düzeltme modu etkin - kullanıcı onayı istenmeyecek");
    } else {
        info!("👤 İnteraktif düzeltme modu - her düzeltme için onay istenecek");
    }

    // Önce tarama yaparak bulguları elde et
    info!("🔍 Mevcut güvenlik bulgularını alıyor...");
    let scanner_manager = scanners::manager::ScannerManager::new();
    let scan_results = scanner_manager.run_all_scans(config);
    
    // Tüm bulguları topla
    let mut all_findings = Vec::new();
    for result in &scan_results {
        all_findings.extend(result.findings.clone());
    }

    if all_findings.is_empty() {
        info!("✅ Düzeltilecek güvenlik açığı bulunamadı!");
        return;
    }

    info!("🎯 {} güvenlik açığı tespit edildi", all_findings.len());

    // Fixer manager oluştur
    let fixer_manager = fixers::manager::FixerManager::new();

    // Belirli modül belirtilmişse sadece o modülü işle
    if let Some(module) = matches.get_one::<String>("module") {
        let filtered_findings: Vec<_> = match module.as_str() {
            "package" => all_findings.iter().filter(|f| f.id.starts_with("PKG-")).cloned().collect(),
            "kernel" => all_findings.iter().filter(|f| f.id.starts_with("KRN-")).cloned().collect(),
            "permission" => all_findings.iter().filter(|f| f.id.starts_with("PERM-")).cloned().collect(),
            "service" => all_findings.iter().filter(|f| f.id.starts_with("SVC-")).cloned().collect(),
            "user" => all_findings.iter().filter(|f| f.id.starts_with("USR-")).cloned().collect(),
            "network" => all_findings.iter().filter(|f| f.id.starts_with("NET-")).cloned().collect(),
            _ => {
                error!("❌ Geçersiz modül: {}. Geçerli modüller: package, kernel, permission, service, user, network", module);
                return;
            }
        };

        if filtered_findings.is_empty() {
            info!("ℹ️  '{}' modülü için düzeltilecek bulgu yok", module);
            return;
        }

        info!("🎯 '{}' modülü için {} bulgu düzeltilecek", module, filtered_findings.len());
        let _results = fixer_manager.fix_findings(&filtered_findings, config, auto_fix);
    } else {
        // Tüm bulguları düzelt
        info!("🚀 Tüm bulgular düzeltilecek...");

        // Önceliğe göre sırala (kritik -> yüksek -> orta -> düşük)
        let prioritized_findings = fixer_manager.prioritize_fixes(&all_findings);
        let prioritized_findings_owned: Vec<_> = prioritized_findings.into_iter().cloned().collect();

        // Düzeltilemeyen bulguları bildir
        let unfixable = fixer_manager.get_unfixable_findings(&all_findings);
        if !unfixable.is_empty() {
            warn!("⚠️  {} bulgu otomatik olarak düzeltilemez:", unfixable.len());
            for finding in unfixable {
                warn!("   • {}: {}", finding.id, finding.title);
            }
        }

        // Düzeltme işlemini başlat
        let _results = fixer_manager.fix_findings(&prioritized_findings_owned, config, auto_fix);
    }

    info!("✅ Düzeltme işlemi tamamlandı!");
}

fn handle_report_command(matches: &ArgMatches, config: &core::config::Config) {
    info!("📊 Rapor oluşturuluyor...");
    
    // Rapor manager oluştur
    let mut report_manager = report::manager::ReportManager::default();
    
    // Çıktı dizinini ayarla
    if let Some(output) = matches.get_one::<String>("output") {
        if std::path::Path::new(output).is_dir() {
            if let Err(e) = report_manager.set_output_directory(output.clone()) {
                error!("❌ Çıktı dizini ayarlanamadı: {}", e);
                return;
            }
            info!("📁 Çıktı dizini: {}", output);
        }
    }

    let security_report = if matches.get_flag("scan") {
        // Yeni tarama yap
        info!("🔍 Yeni tarama başlatılıyor...");
        let scanner_manager = scanners::manager::ScannerManager::new();
        let scan_start = std::time::Instant::now();
        let scan_results = scanner_manager.run_all_scans(config);
        let scan_duration = scan_start.elapsed().as_millis() as u64;
        
        info!("✅ Tarama tamamlandı ({} ms)", scan_duration);
        
        // SecurityReport oluştur
        Some(report::SecurityReport::new(scan_results, None, scan_duration))
        
    } else if let Some(input_file) = matches.get_one::<String>("input") {
        // Mevcut tarama sonuçlarını yükle
        info!("📥 Tarama sonuçları yükleniyor: {}", input_file);
        
        match std::fs::read_to_string(input_file) {
            Ok(json_content) => {
                // Önce SecurityReport olarak okumayı dene
                match serde_json::from_str::<report::SecurityReport>(&json_content) {
                    Ok(security_report) => {
                        info!("✅ SecurityReport yüklendi");
                        Some(security_report)
                    }
                    Err(_) => {
                        // SecurityReport olarak okunamazsa Vec<ScanResult> dene
                        match serde_json::from_str::<Vec<scanners::ScanResult>>(&json_content) {
                            Ok(scan_results) => {
                                info!("✅ {} tarama sonucu yüklendi", scan_results.len());
                                Some(report::SecurityReport::new(scan_results, None, 0))
                            }
                            Err(e) => {
                                error!("❌ JSON parse hatası: {}", e);
                                None
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!("❌ Dosya okuma hatası: {}", e);
                None
            }
        }
    } else {
        // Hızlı tarama yap (input dosyası verilmemişse)
        warn!("⚠️  Girdi dosyası belirtilmedi, hızlı tarama yapılıyor...");
        let scanner_manager = scanners::manager::ScannerManager::new();
        let scan_start = std::time::Instant::now();
        let scan_results = scanner_manager.run_all_scans(config);
        let scan_duration = scan_start.elapsed().as_millis() as u64;
        
        Some(report::SecurityReport::new(scan_results, None, scan_duration))
    };

    let Some(security_report) = security_report else {
        error!("❌ Rapor oluşturulamadı: Geçerli tarama verisi bulunamadı");
        return;
    };

    // Sadece özet isteniyorsa
    if matches.get_flag("summary") {
        if let Err(e) = report_manager.print_report_summary(&security_report) {
            error!("❌ Özet yazdırma hatası: {}", e);
        }
        if let Err(e) = report_manager.print_detailed_statistics(&security_report) {
            error!("❌ İstatistik yazdırma hatası: {}", e);
        }
        return;
    }

    // Rapor formatını al
    let format_str = matches.get_one::<String>("format").unwrap(); // default_value ile garantili
    
    match format_str.as_str() {
        "all" => {
            // Tüm formatları oluştur
            info!("� Tüm rapor formatları oluşturuluyor...");
            
            let base_filename = format!("pinGuard-report-{}", security_report.metadata.report_id);
            
            match report_manager.generate_all_formats(&security_report, Some(base_filename)) {
                Ok(files) => {
                    info!("✅ Tüm raporlar oluşturuldu:");
                    for file in files {
                        info!("   📄 {}", file);
                    }
                }
                Err(e) => {
                    error!("❌ Rapor oluşturma hatası: {}", e);
                }
            }
        }
        
        format_name => {
            // Tek format oluştur
            let report_format = match format_name.parse::<report::ReportFormat>() {
                Ok(format) => format,
                Err(e) => {
                    error!("❌ Geçersiz rapor formatı '{}': {}", format_name, e);
                    info!("✅ Geçerli formatlar: json, html, pdf, all");
                    return;
                }
            };

            info!("📋 {} formatında rapor oluşturuluyor...", format_name.to_uppercase());

            // Çıktı dosya adını belirle
            let output_filename = if let Some(output) = matches.get_one::<String>("output") {
                if std::path::Path::new(output).is_dir() {
                    None // Manager kendi dosya adını oluşturacak
                } else {
                    Some(output.clone())
                }
            } else {
                None
            };

            match report_manager.generate_report(&security_report, &report_format, output_filename) {
                Ok(output_path) => {
                    info!("✅ Rapor başarıyla oluşturuldu: {}", output_path);
                    
                    // Rapor hakkında bilgi ver
                    info!("📊 Rapor bilgileri:");
                    info!("   🆔 Report ID: {}", security_report.metadata.report_id);
                    info!("   📈 Güvenlik puanı: {}/100", security_report.summary.security_score);
                    info!("   🎯 Risk seviyesi: {}", security_report.summary.risk_level);
                    info!("   🔍 Toplam bulgu: {}", security_report.summary.total_findings);
                    info!("   🚨 Kritik: {}", security_report.summary.critical_findings);
                    info!("   🔥 Yüksek: {}", security_report.summary.high_findings);
                    
                    // HTML/PDF raporları için ek bilgi
                    if matches!(&report_format, report::ReportFormat::Html) {
                        info!("💡 Raporu görüntülemek için uygun program ile açın");
                    }
                }
                Err(e) => {
                    error!("❌ Rapor oluşturma hatası: {}", e);
                }
            }
        }
    }

    // Format bilgilerini göster (debug için)
    // Note: verbose, global flag olduğu için buradan kontrol edilemiyor
    // if matches.get_flag("verbose") {
    //     report_manager.print_format_info();
    // }
}

fn handle_config_command(matches: &ArgMatches, config: &core::config::Config) {
    if matches.get_flag("show") {
        info!("📋 Mevcut konfigürasyon:");
        println!("{:#?}", config);
    }
    
    if matches.get_flag("init") {
        info!("🔧 Varsayılan config dosyası oluşturuluyor...");
        // TODO: Config dosyası oluşturma implementasyonu
        info!("⚠️  Config init fonksiyonalitesi henüz implementasyonda...");
    }
}

fn handle_database_command(matches: &ArgMatches, _config: &core::config::Config) {
    match matches.subcommand() {
        Some(("init", _)) => {
            info!("💾 Veritabanı başlatılıyor...");
            match DatabaseManager::new_default() {
                Ok(mut db) => {
                    info!("✅ Veritabanı başarıyla başlatıldı");
                    match db.run_migrations() {
                        Ok(_) => info!("✅ Migration'lar başarıyla uygulandı"),
                        Err(e) => error!("❌ Migration hatası: {}", e),
                    }
                }
                Err(e) => error!("❌ Veritabanı başlatma hatası: {}", e),
            }
        }
        
        Some(("migrate", _)) => {
            info!("🔄 Migration'lar çalıştırılıyor...");
            match DatabaseManager::new_default() {
                Ok(mut db) => {
                    match db.run_migrations() {
                        Ok(_) => info!("✅ Migration'lar başarıyla uygulandı"),
                        Err(e) => error!("❌ Migration hatası: {}", e),
                    }
                }
                Err(e) => error!("❌ Veritabanı bağlantı hatası: {}", e),
            }
        }
        
        Some(("health", _)) => {
            info!("🔍 Veritabanı sağlık kontrolü yapılıyor...");
            match DatabaseManager::new_default() {
                Ok(db) => {
                    match db.health_check() {
                        Ok(health) => {
                            if health.is_healthy() {
                                info!("✅ Veritabanı sağlıklı");
                            } else {
                                warn!("⚠️ Veritabanı sağlık sorunları tespit edildi");
                            }
                        }
                        Err(e) => error!("❌ Sağlık kontrolü hatası: {}", e),
                    }
                }
                Err(e) => error!("❌ Veritabanı bağlantı hatası: {}", e),
            }
        }
        
        Some(("stats", _)) => {
            info!("📊 Veritabanı istatistikleri alınıyor...");
            // TODO: Database stats implementasyonu
            info!("⚠️ Database stats henüz implementasyonda...");
        }
        
        Some(("cleanup", sub_matches)) => {
            let days = *sub_matches.get_one::<u32>("days").unwrap_or(&30);
            info!("🧹 {} günden eski veriler temizleniyor...", days);
            // TODO: Database cleanup implementasyonu
            info!("⚠️ Database cleanup henüz implementasyonda...");
        }
        
        _ => {
            error!("❌ Geçersiz database komutu");
            info!("ℹ️ Kullanılabilir komutlar: init, migrate, health, stats, cleanup");
        }
    }
}

fn handle_cve_command(matches: &ArgMatches, _config: &core::config::Config) {
    // Async runtime oluştur
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            error!("❌ Async runtime hatası: {}", e);
            return;
        }
    };

    rt.block_on(async {
        // Database ve CVE manager'ı başlat
        let db = match DatabaseManager::new_default() {
            Ok(db) => db,
            Err(e) => {
                error!("❌ Veritabanı bağlantı hatası: {}", e);
                return;
            }
        };

        let cve_manager = match CveManager::new(db) {
            Ok(manager) => manager,
            Err(e) => {
                error!("❌ CVE manager hatası: {}", e);
                return;
            }
        };

        match matches.subcommand() {
            Some(("sync", sub_matches)) => {
                let days = *sub_matches.get_one::<u32>("days").unwrap_or(&7);
                info!("🔄 Son {} günün CVE'leri senkronize ediliyor...", days);
                
                match cve_manager.sync_recent_cves(days).await {
                    Ok(count) => info!("✅ {} CVE senkronize edildi", count),
                    Err(e) => error!("❌ CVE senkronizasyon hatası: {}", e),
                }
            }
            
            Some(("search", sub_matches)) => {
                let query = sub_matches.get_one::<String>("query").unwrap();
                let limit = *sub_matches.get_one::<usize>("limit").unwrap_or(&10);
                
                info!("🔍 '{}' için CVE aranıyor (limit: {})...", query, limit);
                
                match cve_manager.find_cves_for_package(query).await {
                    Ok(cves) => {
                        let limited_cves: Vec<_> = cves.into_iter().take(limit).collect();
                        
                        if limited_cves.is_empty() {
                            info!("🔍 '{}' için CVE bulunamadı", query);
                        } else {
                            info!("✅ {} CVE bulundu:", limited_cves.len());
                            for cve in limited_cves {
                                println!("\n📋 {} ({:?})", cve.cve_id, cve.severity);
                                println!("   📝 {}", cve.description);
                                if let Some(score) = cve.score {
                                    println!("   📊 CVSS Score: {:.1}", score);
                                }
                                println!("   📅 Published: {}", cve.published_date.format("%Y-%m-%d"));
                                if !cve.references.is_empty() {
                                    println!("   🔗 References: {}", cve.references.join(", "));
                                }
                            }
                        }
                    }
                    Err(e) => error!("❌ CVE arama hatası: {}", e),
                }
            }
            
            Some(("get", sub_matches)) => {
                let cve_id = sub_matches.get_one::<String>("cve_id").unwrap();
                info!("🔍 CVE detayları alınıyor: {}", cve_id);
                
                match cve_manager.get_cve(cve_id).await {
                    Ok(cve) => {
                        println!("\n📋 CVE Detayları: {}", cve.cve_id);
                        println!("   🔴 Severity: {:?}", cve.severity);
                        println!("   📝 Description: {}", cve.description);
                        if let Some(score) = cve.score {
                            println!("   📊 CVSS Score: {:.1}", score);
                        }
                        if let Some(vector) = &cve.vector_string {
                            println!("   🎯 CVSS Vector: {}", vector);
                        }
                        println!("   📅 Published: {}", cve.published_date.format("%Y-%m-%d"));
                        println!("   🔄 Last Modified: {}", cve.last_modified.format("%Y-%m-%d"));
                        
                        if !cve.affected_packages.is_empty() {
                            println!("   🎯 Affected Products:");
                            for product in &cve.affected_packages {
                                println!("      • {}", product);
                            }
                        }
                        
                        if !cve.references.is_empty() {
                            println!("   🔗 References:");
                            for reference in &cve.references {
                                println!("      • {}", reference);
                            }
                        }
                        
                        if !cve.cpe_matches.is_empty() {
                            println!("   💻 CPE Matches: {} configurations", cve.cpe_matches.len());
                        }
                    }
                    Err(e) => error!("❌ CVE getirme hatası: {}", e),
                }
            }
            
            Some(("health", _)) => {
                info!("🔍 CVE manager sağlık kontrolü yapılıyor...");
                
                match cve_manager.health_check().await {
                    Ok(health) => {
                        println!("\n📊 CVE Manager Sağlık Durumu:");
                        println!("   🌐 NVD API: {}", if health.nvd_api_healthy { "✅ Sağlıklı" } else { "❌ Sorunlu" });
                        println!("   📊 Response Time: {} ms", health.nvd_response_time_ms);
                        println!("   💾 Cache: {}", if health.cache_healthy { "✅ Sağlıklı" } else { "❌ Sorunlu" });
                        println!("   📋 Cache Entries: {}", health.cache_entries);
                        println!("   📈 Hit Rate: {:.1}%", health.cache_hit_rate * 100.0);
                        println!("   💽 Cache Size: {:.2} MB", health.cache_size_mb);
                        println!("   🔄 Auto Refresh: {}", if health.auto_refresh_enabled { "✅ Etkin" } else { "❌ Devre dışı" });
                        println!("   🛡️ Fallback: {}", if health.fallback_enabled { "✅ Etkin" } else { "❌ Devre dışı" });
                        println!("   🕐 Last Check: {}", health.last_check.format("%Y-%m-%d %H:%M:%S UTC"));
                        
                        if health.is_healthy() {
                            info!("✅ CVE manager tamamen sağlıklı");
                        } else {
                            warn!("⚠️ CVE manager'da sorunlar tespit edildi");
                        }
                    }
                    Err(e) => error!("❌ Sağlık kontrolü hatası: {}", e),
                }
            }
            
            Some(("cache", cache_matches)) => {
                match cache_matches.subcommand() {
                    Some(("stats", _)) => {
                        info!("📊 CVE cache istatistikleri alınıyor...");
                        // TODO: Cache stats implementasyonu
                        info!("⚠️ Cache stats henüz implementasyonda...");
                    }
                    
                    Some(("cleanup", _)) => {
                        info!("🧹 Expire olmuş cache temizleniyor...");
                        match cve_manager.maintain_cache().await {
                            Ok(result) => {
                                info!("✅ Cache maintenance tamamlandı:");
                                info!("   🗑️ Temizlenen entries: {}", result.expired_entries_cleaned);
                                info!("   📋 Toplam entries: {}", result.total_entries);
                                info!("   💽 Cache boyutu: {:.2} MB", result.cache_size_mb);
                                info!("   🔄 Sync edilen CVE: {}", result.synced_recent_cves);
                            }
                            Err(e) => error!("❌ Cache maintenance hatası: {}", e),
                        }
                    }
                    
                    Some(("refresh", _)) => {
                        info!("🔄 Cache yenileniyor...");
                        match cve_manager.sync_recent_cves(1).await {
                            Ok(count) => info!("✅ {} fresh CVE cache'e eklendi", count),
                            Err(e) => error!("❌ Cache refresh hatası: {}", e),
                        }
                    }
                    
                    _ => {
                        error!("❌ Geçersiz cache komutu");
                        info!("ℹ️ Kullanılabilir komutlar: stats, cleanup, refresh");
                    }
                }
            }
            
            _ => {
                error!("❌ Geçersiz CVE komutu");
                info!("ℹ️ Kullanılabilir komutlar: sync, search, get, health, cache");
            }
        }
    });
}

fn handle_schedule_command(matches: &ArgMatches, config: &core::config::Config) {
    info!("⏰ Schedule komutu çalıştırılıyor...");

    // Database bağlantısını kur
    let db = match DatabaseManager::new(&config.database.path) {
        Ok(db) => db,
        Err(e) => {
            error!("❌ Database bağlantı hatası: {}", e);
            return;
        }
    };

    // Scheduler'ı oluştur
    let mut scheduler = match Scheduler::new(db) {
        Ok(scheduler) => scheduler,
        Err(e) => {
            error!("❌ Scheduler oluşturma hatası: {}", e);
            return;
        }
    };

    match matches.subcommand() {
        Some(("enable", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").unwrap();
            let schedule = sub_matches.get_one::<String>("schedule").unwrap();
            let description = sub_matches.get_one::<String>("description")
                .map(|s| s.as_str())
                .unwrap_or("Scheduled security scan");
            let scan_type_str = sub_matches.get_one::<String>("type").unwrap();

            let scan_type = match scan_type_str.as_str() {
                "full" => scheduler::ScanType::Full,
                "quick" => scheduler::ScanType::Quick,
                "security" => scheduler::ScanType::Security,
                _ => {
                    error!("❌ Geçersiz tarama türü: {}", scan_type_str);
                    info!("ℹ️ Geçerli türler: full, quick, security");
                    return;
                }
            };

            let schedule_config = scheduler::ScheduleConfig::new(
                name.clone(),
                description.to_string(),
                schedule.clone(),
                scan_type,
            );

            info!("🔧 Schedule etkinleştiriliyor: {}", name);
            match scheduler.enable(schedule_config) {
                Ok(_) => {
                    info!("✅ Schedule başarıyla etkinleştirildi: {}", name);
                    info!("   📅 Zamanlama: {}", schedule);
                    info!("   📝 Açıklama: {}", description);
                    info!("   🔧 Systemd timer ve service dosyaları oluşturuldu");
                }
                Err(e) => {
                    error!("❌ Schedule etkinleştirme hatası: {}", e);
                }
            }
        }

        Some(("disable", sub_matches)) => {
            let name = sub_matches.get_one::<String>("name").unwrap();
            
            info!("🛑 Schedule devre dışı bırakılıyor: {}", name);
            match scheduler.disable(name) {
                Ok(_) => {
                    info!("✅ Schedule başarıyla devre dışı bırakıldı: {}", name);
                    info!("   🗑️ Systemd timer ve service dosyaları kaldırıldı");
                }
                Err(e) => {
                    error!("❌ Schedule devre dışı bırakma hatası: {}", e);
                }
            }
        }

        Some(("list", _)) => {
            info!("📋 Aktif schedule'lar listeleniyor...");
            match scheduler.list_schedules() {
                Ok(schedules) => {
                    if schedules.is_empty() {
                        info!("📄 Henüz aktif schedule yok");
                        info!("ℹ️ 'pinGuard schedule presets' ile hazır schedule'ları yükleyebilirsiniz");
                    } else {
                        info!("📋 {} aktif schedule bulundu:", schedules.len());
                        for schedule in schedules {
                            println!();
                            println!("   📅 {}", schedule.name);
                            println!("      ⏰ Zamanlama: {}", schedule.schedule);
                            println!("      📝 Açıklama: {}", schedule.description);
                            println!("      🔧 Türü: {}", schedule.scan_type);
                            println!("      ✅ Durum: {}", if schedule.enabled { "Etkin" } else { "Devre dışı" });
                            println!("      📊 Modüller: {}", schedule.scan_modules.join(", "));
                        }
                    }
                }
                Err(e) => {
                    error!("❌ Schedule listesi alınamadı: {}", e);
                }
            }
        }

        Some(("status", sub_matches)) => {
            if let Some(name) = sub_matches.get_one::<String>("name") {
                // Belirli bir schedule'ın durumu
                info!("🔍 Schedule durumu kontrol ediliyor: {}", name);
                match scheduler.get_schedule_status(name) {
                    Ok(status) => {
                        println!();
                        println!("📊 Schedule Durumu: {}", status.name);
                        println!("   ✅ Etkin: {}", if status.enabled { "Evet" } else { "Hayır" });
                        println!("   🔄 Aktif: {}", if status.active { "Evet" } else { "Hayır" });
                        println!("   ⏰ Zamanlama: {}", status.config.schedule);
                        println!("   📝 Açıklama: {}", status.config.description);
                        
                        if let Some(last_run) = status.last_run {
                            println!("   🏃 Son çalışma: {}", last_run.run_time.format("%Y-%m-%d %H:%M:%S UTC"));
                            println!("   ✅ Başarılı: {}", if last_run.success { "Evet" } else { "Hayır" });
                            println!("   ⏱️ Süre: {}ms", last_run.duration_ms);
                            println!("   📊 Finding sayısı: {}", last_run.findings_count);
                            if let Some(error) = last_run.error_message {
                                println!("   ❌ Hata: {}", error);
                            }
                        }
                        
                        if let Some(next_run) = status.next_run {
                            println!("   ⏭️ Bir sonraki çalışma: {}", next_run.format("%Y-%m-%d %H:%M:%S UTC"));
                        }
                    }
                    Err(e) => {
                        error!("❌ Schedule durumu alınamadı: {}", e);
                    }
                }
            } else {
                // Tüm schedule'ların durumu
                info!("🔍 Tüm schedule durumları kontrol ediliyor...");
                match scheduler.get_all_statuses() {
                    Ok(statuses) => {
                        if statuses.is_empty() {
                            info!("📄 Aktif schedule yok");
                        } else {
                            println!();
                            println!("📊 Schedule Durumları ({})", statuses.len());
                            for status in statuses {
                                println!();
                                println!("   📅 {}", status.name);
                                println!("      ✅ Etkin: {} | 🔄 Aktif: {}", 
                                    if status.enabled { "Evet" } else { "Hayır" },
                                    if status.active { "Evet" } else { "Hayır" }
                                );
                                if let Some(next_run) = status.next_run {
                                    println!("      ⏭️ Sonraki: {}", next_run.format("%Y-%m-%d %H:%M"));
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ Schedule durumları alınamadı: {}", e);
                    }
                }
            }
        }

        Some(("presets", _)) => {
            info!("🔧 Hazır schedule şablonları yükleniyor...");
            match scheduler.schedule_manager.create_default_schedules() {
                Ok(_) => {
                    info!("✅ Hazır schedule'lar başarıyla oluşturuldu:");
                    info!("   📅 daily-full: Her gün 02:00'da tam tarama");
                    info!("   📅 weekly-full: Her pazar 03:00'da tam tarama");
                    info!("   📅 quick-3x: Günde 3 kez hızlı tarama (06:00, 12:00, 18:00)");
                    info!("ℹ️ Bu schedule'ları etkinleştirmek için 'schedule enable' komutunu kullanın");
                }
                Err(e) => {
                    error!("❌ Hazır schedule'lar oluşturulamadı: {}", e);
                }
            }
        }

        _ => {
            error!("❌ Geçersiz schedule komutu");
            info!("ℹ️ Kullanılabilir komutlar: enable, disable, list, status, presets");
        }
    }
}

fn handle_run_scheduled_scan(matches: &ArgMatches, config: &core::config::Config) {
    let schedule_name = matches.get_one::<String>("schedule_name").unwrap();
    
    info!("🤖 Planlı tarama çalıştırılıyor: {}", schedule_name);

    // Database bağlantısını kur
    let db = match DatabaseManager::new(&config.database.path) {
        Ok(db) => db,
        Err(e) => {
            error!("❌ Database bağlantı hatası: {}", e);
            std::process::exit(1);
        }
    };

    // Scheduler'ı oluştur
    let scheduler = match Scheduler::new(db) {
        Ok(scheduler) => scheduler,
        Err(e) => {
            error!("❌ Scheduler oluşturma hatası: {}", e);
            std::process::exit(1);
        }
    };

    // Async runtime'ı başlat ve scheduled scan'i çalıştır
    let rt = tokio::runtime::Runtime::new().unwrap();
    match rt.block_on(scheduler.run_scheduled_scan(schedule_name)) {
        Ok(_) => {
            info!("✅ Planlı tarama başarıyla tamamlandı: {}", schedule_name);
        }
        Err(e) => {
            error!("❌ Planlı tarama hatası: {}", e);
            std::process::exit(1);
        }
    }
}
