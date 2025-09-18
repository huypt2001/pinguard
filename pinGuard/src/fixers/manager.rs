use super::{Fixer, FixResult, FixError, FixPlan, FixStatus};
use crate::core::config::Config;
use crate::scanners::Finding;
use crate::fixers::{
    package_updater::PackageUpdater,
    kernel_updater::KernelUpdater,
    permission_fixer::PermissionFixer,
    service_hardener::ServiceHardener,
    user_policy_fixer::UserPolicyFixer,
    firewall_configurator::FirewallConfigurator,
};
use std::io::{self, Write};

pub struct FixerManager {
    fixers: Vec<Box<dyn Fixer>>,
}

impl FixerManager {
    pub fn new() -> Self {
        let mut fixers: Vec<Box<dyn Fixer>> = Vec::new();
        
        // Mevcut fixer'ları ekle
        fixers.push(Box::new(PackageUpdater));
        fixers.push(Box::new(KernelUpdater));
        fixers.push(Box::new(PermissionFixer));
        fixers.push(Box::new(ServiceHardener));
        fixers.push(Box::new(UserPolicyFixer));
        fixers.push(Box::new(FirewallConfigurator));
        
        Self { fixers }
    }

    /// Belirli bir bulgu için uygun fixer'ı bul ve çalıştır
    pub fn fix_finding(&self, finding: &Finding, config: &Config, auto_approve: bool) -> Result<FixResult, FixError> {
        // Bulguyu düzeltebilecek fixer'ı bul
        let fixer = self.fixers.iter()
            .find(|f| f.can_fix(finding))
            .ok_or_else(|| FixError::UnsupportedFix(format!("No fixer available for: {}", finding.id)))?;

        tracing::info!("Fixer bulundu: {} -> {}", finding.id, fixer.name());

        // Kullanıcı onayı iste (eğer auto_approve false ise)
        if !auto_approve {
            let plan = fixer.dry_run(finding)?;
            if !self.get_user_approval(&plan)? {
                return Ok(FixResult::new(finding.id.clone(), fixer.name().to_string())
                    .with_status(FixStatus::Cancelled)
                    .with_message("Fix cancelled by user".to_string()));
            }
        }

        // Düzeltmeyi uygula
        fixer.fix(finding, config)
    }

    /// Birden fazla bulguyu toplu olarak düzelt
    pub fn fix_findings(&self, findings: &[Finding], config: &Config, auto_approve: bool) -> Vec<FixResult> {
        let mut results = Vec::new();

        tracing::info!("{} bulgu için düzeltme işlemi başlatılıyor...", findings.len());

        for finding in findings {
            match self.fix_finding(finding, config, auto_approve) {
                Ok(result) => {
                    tracing::info!("{} düzeltildi: {}", finding.id, result.message);
                    results.push(result);
                }
                Err(e) => {
                    tracing::error!("{} düzeltilemedi: {}", finding.id, e);
                    let error_result = FixResult::new(finding.id.clone(), "Unknown".to_string())
                        .with_status(FixStatus::Failed)
                        .with_message(format!("Fix failed: {}", e));
                    results.push(error_result);
                }
            }
        }

        self.print_fix_summary(&results);
        results
    }

    /// Kullanıcıdan onay iste
    fn get_user_approval(&self, plan: &FixPlan) -> Result<bool, FixError> {
        println!("Düzeltme Planı:");
        println!("ID: {}", plan.finding_id);
        println!("Fixer: {}", plan.fixer_name);
        println!("Açıklama: {}", plan.description);
        println!("Risk Seviyesi: {:?}", plan.risk_level);
        println!("Tahmini Süre: {:?}", plan.estimated_duration);

        if !plan.commands_to_execute.is_empty() {
            println!("Çalıştırılacak Komutlar:");
            for cmd in &plan.commands_to_execute {
                println!("    • {}", cmd);
            }
        }

        if !plan.files_to_modify.is_empty() {
            println!("Değiştirilecek Dosyalar:");
            for file in &plan.files_to_modify {
                println!("    • {}", file);
            }
        }

        if plan.backup_required {
            println!("Backup oluşturulacak: Evet");
        }

        if plan.reboot_required {
            println!("Yeniden başlatma gerekli: Evet");
        }

        print!("Bu düzeltmeyi uygulamak istiyorsunız? [y/N]: ");
        io::stdout().flush().map_err(|e| FixError::IoError(format!("Stdout flush error: {}", e)))?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)
            .map_err(|e| FixError::IoError(format!("Input read error: {}", e)))?;

        let response = input.trim().to_lowercase();
        Ok(response == "y" || response == "yes" || response == "evet")
    }

    /// Düzeltme özeti yazdır
    fn print_fix_summary(&self, results: &[FixResult]) {
        println!("Düzeltme Özeti:");
        
        let successful = results.iter().filter(|r| r.status == FixStatus::Success).count();
        let failed = results.iter().filter(|r| r.status == FixStatus::Failed).count();
        let cancelled = results.iter().filter(|r| r.status == FixStatus::Cancelled).count();
        let requires_action = results.iter().filter(|r| r.status == FixStatus::RequiresUserAction).count();
        let requires_reboot = results.iter().filter(|r| r.status == FixStatus::RequiresReboot).count();

        println!("Toplam: {}", results.len());
        println!("Başarılı: {}", successful);
        println!("Başarısız: {}", failed);
        println!("İptal Edildi: {}", cancelled);
        println!("Kullanıcı Eylemi Gerekli: {}", requires_action);
        println!("Yeniden Başlatma Gerekli: {}", requires_reboot);

        // Detayları göster
        for result in results {
            match result.status {
                FixStatus::Success => println!("{}: {}", result.finding_id, result.message),
                FixStatus::Failed => println!("{}: {}", result.finding_id, result.message),
                FixStatus::RequiresUserAction => println!("{}: {}", result.finding_id, result.message),
                FixStatus::RequiresReboot => println!("{}: {}", result.finding_id, result.message),
                FixStatus::Cancelled => println!("{}: {}", result.finding_id, result.message),
                _ => {}
            }
        }

        // Yeniden başlatma uyarısı
        if requires_reboot > 0 {
            println!("UYARI: {} düzeltme yeniden başlatma gerektiriyor!", requires_reboot);
            println!("   Sistemin tam güvenli hale gelmesi için yeniden başlatın: sudo reboot");
        }

        // Backup bilgisi
        let backup_count = results.iter().filter(|r| r.backup_created.is_some()).count();
        if backup_count > 0 {
            println!("\n{} dosya için backup oluşturuldu:", backup_count);
            for result in results {
                if let Some(backup_path) = &result.backup_created {
                    println!("   • {}", backup_path);
                }
            }
        }
    }

    /// Bulguları düzeltme önceliğine göre sırala
    pub fn prioritize_fixes<'a>(&self, findings: &'a [Finding]) -> Vec<&'a Finding> {
        let mut prioritized = findings.iter().collect::<Vec<_>>();
        
        prioritized.sort_by(|a, b| {
            // Öncelik sırası: Kritik > Yüksek > Orta > Düşük
            let a_priority = match a.severity {
                crate::scanners::Severity::Critical => 4,
                crate::scanners::Severity::High => 3,
                crate::scanners::Severity::Medium => 2,
                crate::scanners::Severity::Low => 1,
                crate::scanners::Severity::Info => 0,
            };
            
            let b_priority = match b.severity {
                crate::scanners::Severity::Critical => 4,
                crate::scanners::Severity::High => 3,
                crate::scanners::Severity::Medium => 2,
                crate::scanners::Severity::Low => 1,
                crate::scanners::Severity::Info => 0,
            };
            
            b_priority.cmp(&a_priority)
        });
        
        prioritized
    }

    /// Sadece belirli kategorilerdeki bulguları düzelt
    pub fn fix_by_category(&self, findings: &[Finding], category: &crate::scanners::Category, config: &Config, auto_approve: bool) -> Vec<FixResult> {
        let filtered_findings: Vec<&Finding> = findings.iter()
            .filter(|f| f.category == *category)
            .collect();

        tracing::info!("{:?} kategorisinde {} bulgu düzeltilecek", category, filtered_findings.len());

        self.fix_findings(&filtered_findings.into_iter().cloned().collect::<Vec<_>>(), config, auto_approve)
    }

    /// Kapsamlı sistem sertleştirmesi
    pub fn comprehensive_hardening(&self, config: &Config) -> Result<Vec<FixResult>, FixError> {
        let mut results = Vec::new();

        tracing::info!("Kapsamlı sistem sertleştirmesi başlatılıyor...");

        // Service hardening
        let service_hardener = ServiceHardener;
        match service_hardener.disable_all_risky_services() {
            Ok(mut service_results) => results.append(&mut service_results),
            Err(e) => tracing::error!("Service hardening failed: {}", e),
        }

        // User policy hardening
        let user_policy_fixer = UserPolicyFixer;
        match user_policy_fixer.fix_all_password_policies() {
            Ok(mut user_results) => results.append(&mut user_results),
            Err(e) => tracing::error!("User policy hardening failed: {}", e),
        }

        // Firewall configuration
        let firewall_configurator = FirewallConfigurator;
        match firewall_configurator.configure_comprehensive_firewall() {
            Ok(mut firewall_results) => results.append(&mut firewall_results),
            Err(e) => tracing::error!("Firewall configuration failed: {}", e),
        }

        // Permission fixing
        let permission_fixer = PermissionFixer;
        match permission_fixer.fix_all_critical_permissions() {
            Ok(mut permission_results) => results.append(&mut permission_results),
            Err(e) => tracing::error!("Permission fixing failed: {}", e),
        }

        tracing::info!("Kapsamlı sistem sertleştirmesi tamamlandı: {} işlem", results.len());

        Ok(results)
    }

    /// Mevcut fixer'ları listele
    pub fn list_fixers(&self) -> Vec<&str> {
        self.fixers.iter().map(|f| f.name()).collect()
    }

    /// Belirli bir fixer'ın düzeltebileceği bulguları filtrele
    pub fn get_fixable_findings<'a>(&self, findings: &'a [Finding], fixer_name: &str) -> Vec<&'a Finding> {
        let fixer = self.fixers.iter()
            .find(|f| f.name() == fixer_name);

        if let Some(fixer) = fixer {
            findings.iter()
                .filter(|f| fixer.can_fix(f))
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Tüm düzeltilemeyen bulguları listele
    pub fn get_unfixable_findings<'a>(&self, findings: &'a [Finding]) -> Vec<&'a Finding> {
        findings.iter()
            .filter(|finding| {
                !self.fixers.iter().any(|fixer| fixer.can_fix(finding))
            })
            .collect()
    }
}