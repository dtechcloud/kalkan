# SPDX-License-Identifier: MIT
"""UI strings of the report in Turkish and English (docs/ENGINE-SPEC.md, section 16).

The Turkish strings use clear, simple Turkish and keep established English technical terms in
English (``knowledge/glossary.md``): SQL injection, XSS, payload, sink, PoC, SBOM, CVE, CWE,
CVSS, SARIF, false positive, reachability and others.

:func:`t` returns one string. Placeholders use :meth:`str.format` with keyword arguments. Label
functions (:func:`severity_label`, :func:`verdict_label` and others) map engine values to UI
labels and return the raw value for an unknown key, so that a new engine value never crashes the
report.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

__all__ = [
    "LANGUAGES",
    "STRINGS",
    "answer_label",
    "condition_label",
    "confidence_label",
    "engine_status_label",
    "ledger_status_label",
    "phase_label",
    "phase_status_label",
    "poc_level_label",
    "poc_status_label",
    "profile_label",
    "question_label",
    "reachability_label",
    "review_label",
    "runtime_validation",
    "sbom_source_label",
    "severity_label",
    "t",
    "trace_kind_label",
    "verdict_label",
]

LANGUAGES: Final = ("tr", "en")

_TR: Final[dict[str, str]] = {
    # Document
    "doc_title": "Güvenlik denetim raporu",
    "doc_kicker": "GÜVENLİK DENETİMİ",
    "doc_subtitle": "kalkan denetim çıktısı: doğrulanan bulgular, araç sonuçları ve kapsam.",
    "contents": "İçindekiler",
    "theme_toggle": "Tema",
    "lang_name": "Türkçe",
    # Metadata
    "meta_field": "Alan",
    "meta_value": "Değer",
    "meta_run_id": "Çalıştırma ID",
    "meta_target": "Hedef",
    "meta_target_kind": "Hedef türü",
    "meta_git_ref": "Git commit",
    "meta_profile": "Profil",
    "meta_lang": "Çalıştırma dili",
    "meta_created": "Başlangıç",
    "meta_updated": "Son güncelleme",
    "meta_generated": "Rapor tarihi",
    "meta_phase": "Aşama",
    "meta_status": "Durum",
    "meta_tech": "Teknolojiler",
    "kind_path": "Yerel klasör",
    "kind_git": "Git deposu",
    "status_complete": "Tamamlandı",
    "status_incomplete": "Tamamlanmadı",
    "status_unknown": "Bilinmiyor",
    "none": "Yok",
    "unknown": "Bilinmiyor",
    "dash": "—",
    # Sections
    "sec_summary": "Yönetici özeti",
    "sec_scope": "Kapsam",
    "sec_confirmed": "Doğrulanan bulgular",
    "sec_needs_validation": "Doğrulama gerektiren bulgular",
    "sec_rejected": "Reddedilen bulgular",
    "sec_hardening": "Hardening notları",
    "sec_tool_results": "Araç sonuçları (doğrulanmadı)",
    "sec_sca": "Bağımlılık zafiyetleri (SCA)",
    "sec_appendix": "Ek A. Yöntem ve kaynaklar",
    "appendix_short": "Ek A",
    "sub_profile_budget": "Profil ve bütçe",
    "sub_phases": "Aşamalar",
    "sub_engines": "Tarayıcılar",
    "sub_ledger": "Kapsam defteri (coverage ledger)",
    "sub_missing": "Eksik girdiler",
    "sub_method": "Yöntem",
    "sub_tool_versions": "Araç sürümleri",
    "sub_run": "Çalıştırma",
    "sub_findings_table": "Bulgu listesi",
    "sub_unvalidated": "Doğrulanamayan adaylar",
    "unvalidated_intro": "Doğrulama bütçesi bitti. Bu hunter adayları için verify görevi "
    "çalışmadı. Bunlar bulgu değil. Her adayın kapsam birimi açık kaldı "
    "(`validation_budget_exhausted`).",
    "col_fingerprint": "Fingerprint",
    "col_suggested": "Önerilen etki / olasılık",
    "col_units": "Kapsam birimi",
    # Summary
    "summary_confirmed": "kalkan {n} bulguyu doğruladı.",
    "summary_confirmed_none": "kalkan doğrulanmış bulgu bulmadı.",
    "summary_highest": "En yüksek ciddiyet: {label}.",
    "summary_needs_validation": "{n} bulgu doğrulama bekliyor.",
    "summary_rejected": "Doğrulayıcı {n} aday bulguyu reddetti.",
    "summary_tool_results": "Araçlar {n} doğrulanmamış sonuç verdi.",
    "summary_sca": "SCA {n} bağımlılık zafiyeti buldu. {reachable} kayıt erişilebilir (reachable).",
    "summary_malicious": "Dikkat: {n} bağımlılık bilinen zararlı paket sürümü. Bu paketler "
    "kurulurken kod çalıştırır. 8.1 bölümündeki adımları hemen uygula.",
    "summary_findings_missing": "`findings.json` yok. Birleştirme (merge) adımı çalışmadı.",
    "summary_unvalidated": "Bütçe bittiği için {n} hunter adayı doğrulanamadı.",
    "summary_partial": "Bu rapor hedefin tamamını kapsamıyor olabilir. Sebepler 2. bölümde.",
    "kpi_confirmed": "Doğrulanan bulgu",
    "kpi_needs_validation": "Doğrulama bekleyen",
    "kpi_rejected": "Reddedilen",
    "kpi_tool_results": "Doğrulanmamış araç sonucu",
    "kpi_sca": "SCA kaydı",
    "kpi_sca_malicious": "Zararlı bağımlılık",
    "kpi_severity_note": "Ciddiyet sayıları yalnızca doğrulanan bulguları kapsar.",
    "count_table_metric": "Ölçüt",
    "count_table_count": "Sayı",
    # Partial pass
    "partial_title": "Kısmi geçiş (partial pass)",
    "partial_intro": "Bu rapor hedefin tamamını kapsamıyor olabilir. Sebepler:",
    "partial_full": "Bu çalıştırma tamamlandı. Kapsam defterinde açık birim yok.",
    "partial_fast": "`fast` profili kullanıldı. Bu profil en çok {max} ajan görevi çalıştırır.",
    "partial_budget": "Ajan görevi bütçesi doldu: {used} / {max}.",
    "partial_not_done": "Çalıştırma bitmedi. Son aşama: {phase}.",
    "partial_reason": "Çalıştırma eksik kaldı: {reason}",
    "partial_ledger_open": "{n} kapsam birimi kapanmadı (planned, in_progress, deferred veya "
    "blocked).",
    "partial_dead_tasks": "{n} ajan görevi bütün denemelerde başarısız oldu.",
    "partial_unvalidated": "Bütçe bittiği için {n} hunter adayı doğrulanamadı. Liste 1. bölümde.",
    "partial_no_state": "`state.json` yok. Çalıştırmanın durumu bilinmiyor.",
    "partial_unchecked_manifests": "{n} bağımlılık manifest dosyasının lockfile dosyası yok. SCA "
    "bu dosyaların sürüm aralıklarını ve dolaylı bağımlılıklarını kontrol etmedi.",
    "partial_database_gaps": "{n} SCA eşleştirme boşluğu var: yerel güvenlik açığı veritabanı "
    "eksikti. kalkan paketleri çevrimiçi bir servise sormaz.",
    "partial_tools_only": "Yalnızca araç modu (tools-only): hiçbir ajan sonuçları doğrulamadı. "
    "Bütün sonuçlar doğrulanmamış araç sonucudur.",
    # Coverage gaps
    "sub_gaps": "Tarama boşlukları",
    "gaps_intro": "Araçlar bu dosyaları tam olarak tarayamadı. Bu dosyalarda sonuç olmaması, "
    "dosyanın temiz olduğunu göstermez.",
    "gaps_manifests": "Bu manifest dosyalarının yanında lockfile yok. SCA araçları paket "
    "sürümlerini ve dolaylı bağımlılıkları lockfile dosyasından okur. kalkan bu dosyaların tam "
    "sürümlerini (exact pin) ayrıca kontrol etti.",
    "gaps_databases": "Bu SCA araçlarının yerel güvenlik açığı veritabanı yoktu. Bu yüzden "
    "aşağıdaki paketleri kontrol etmediler. kalkan paket adlarını ve sürümlerini hiçbir çevrimiçi "
    "servise göndermez. Çözüm: `kalkan sca update-db`, sonra yeni bir çalıştırma.",
    "gaps_db_all": "tüm ekosistemler",
    "gaps_partial": "{engine} {n} dosyayı yalnızca kısmen analiz etti (parse hatası veya araç "
    "içi hata).",
    "gaps_skipped": "{engine} {n} dosyayı atladı.",
    "gaps_reasons": "Sebepler",
    "gaps_files": "Dosyalar",
    "gaps_more": "Listede olmayan {n} dosya daha var.",
    "gaps_packages_gosec": "{engine} {n} Go paketini hatayla yükledi. Bu paketlerde tip bilgisi "
    "ve SSA gerektiren kontroller çalışmadı. Sözdizimi kontrolleri çalıştı.",
    "gaps_packages_govulncheck": "{engine} {n} Go paketini yükleyemedi. Bu yüzden Go "
    "kayıtlarının erişilebilirliğini kontrol etmedi.",
    "gaps_packages": "{engine} {n} Go paketini hatayla yükledi.",
    "gaps_packages_more": "Listede olmayan {n} paket daha var.",
    "gaps_package_missing_local": "{names} modülü yerel modül önbelleğinde veya bir `vendor` "
    "klasöründe yok. Yerel mod Go modülü indirmez (`GOPROXY=off`).",
    "gaps_package_missing_online": "{names} modülü yüklenemedi.",
    "gaps_package_missing_import": "içe aktarılan bir paket",
    "gaps_package_error": "Paket yükleme hatası (sözdizimi veya tip hatası).",
    "gaps_packages_fix_gosec": "Çözüm: `kalkan scan gosec --online` (hedefin Go modüllerini "
    "indirir) veya hedefte bir `vendor/` klasörü. İkisi de gosec'e tam tip bilgisi verir.",
    "gaps_packages_fix_govulncheck": "Çözüm: `kalkan sca reach --online` (hedefin Go "
    "modüllerini indirir) veya hedefte bir `vendor/` klasörü.",
    "gaps_long_paths": "{n} dosyanın tam yolu {limit} veya daha fazla karakter. Opengrep bu "
    "dosyaları uyarı vermeden atlayabilir. Sebep: Opengrep'in çekirdek programı uzun yolları "
    "desteklemiyor. LongPathsEnabled=1 bu sınırı kaldırmıyor.",
    "gaps_long_paths_registry": "Bu makinede LongPathsEnabled: {value}.",
    "gaps_long_paths_fix": "Çözüm: `KALKAN_RUNS_DIR` değişkenini kısa bir klasöre (örneğin "
    "`C:/kr`) ayarla. Sonra yeni bir çalıştırma başlat.",
    "value_on": "açık",
    "value_off": "kapalı",
    "col_file": "Dosya",
    "col_exact_pins": "Kontrol edilen tam sürüm",
    "col_ranges": "Kontrol edilmeyen aralık",
    "reason_ranges": "Sürüm aralıkları var, lockfile yok",
    "reason_pins_only": "Yalnızca tam sürümler var. Dolaylı bağımlılıklar kontrol edilmedi.",
    "reason_unreadable": "Dosya okunamadı",
    # Scope
    "scope_profile": "Profil: {profile}.",
    "scope_budget": "Ajan görevi bütçesi: {used} / {max} kullanıldı.",
    "scope_budget_missing": "Bütçe bilgisi yok.",
    "col_phase": "Aşama",
    "col_status": "Durum",
    "col_started": "Başlangıç",
    "col_finished": "Bitiş",
    "col_engine": "Motor",
    "col_group": "Grup",
    "col_version": "Sürüm",
    "col_duration": "Süre",
    "col_message": "Not",
    "col_ledger_status": "Birim durumu",
    "col_count": "Sayı",
    "col_total": "Toplam",
    "phases_missing": "Aşama bilgisi yok (`state.json` okunamadı).",
    "engines_missing": "Tarayıcı durum dosyası yok (`scans/*.status.json`, `sca/*.status.json`).",
    "ledger_missing": "`coverage-ledger.json` yok. Kapsam birimi sayısı bilinmiyor.",
    "ledger_empty": "Kapsam defterinde birim yok.",
    "ledger_sibling_closed": "{n} birim önce Engellendi (blocked) durumundaydı. Critic bu "
    "birimleri kapattı, çünkü kardeş birimler eksik bilgiyi veren kodu okudu. Engine her alıntıyı "
    "kaynak kodla karşılaştırdı. Tablo bu birimleri İncelendi (covered) satırında sayar.",
    "review_counts": "{reviewed} kayıt ikinci, bağımsız bir incelemeden geçti: {verified} "
    "doğrulandı, {downgrade} düşürüldü, {reject} reddedildi. İncelenmeyen doğrulanmış veya "
    "doğrulama bekleyen kayıt: {not_reviewed}.",
    "review_fast": "`fast` profilinde ayrı bir son inceleme yok. Doğrulama görevi kayıt "
    "kontrollerini de yapar (Cloudflare quick profili).",
    "missing_intro": "Bu girdiler yok veya okunamadı. Rapor yalnızca var olan verileri gösterir.",
    "missing_none": "Bütün girdiler okundu.",
    "group_scans": "Tarama",
    "group_sca": "SCA",
    "seconds": "{s} sn",
    # Findings
    "findings_none_confirmed": "Doğrulanan bulgu yok.",
    "findings_none_needs_validation": "Doğrulama bekleyen bulgu yok.",
    "findings_none_rejected": "Reddedilen bulgu yok.",
    "confirmed_intro": "Motor bir bulguyu iki yolla doğrular: üç soru, motorun kaynakta "
    "bulduğu alıntılarla kanıtlanır veya sandbox içindeki PoC zafiyeti gösterir. Bulgular "
    "ciddiyete göre sıralı.",
    "needs_validation_intro": "Bu bulgular için kanıt eksik. Ciddiyet verilmez. Engelleri ve "
    "doğrulama planını oku.",
    "rejected_intro": "Doğrulayıcı veya son inceleme bu adayları reddetti. Kayıtlar iz için "
    "duruyor.",
    "translation_scope": "",
    "col_id": "ID",
    "col_title": "Başlık",
    "col_severity": "Ciddiyet",
    "col_verdict": "Karar",
    "col_class": "Sınıf",
    "col_location": "Konum",
    "col_reason": "Gerekçe",
    "col_poc": "PoC",
    "f_id": "ID",
    "f_severity": "Ciddiyet",
    "f_severity_detail": "{overall} (olasılık: {likelihood}, etki: {impact})",
    "f_cvss": "CVSS",
    "f_confidence": "Güven",
    "f_class": "Sınıf",
    "f_cwe": "CWE",
    "f_owasp": "OWASP",
    "f_location": "Konum",
    "f_engines": "Motorlar",
    "f_review": "Son inceleme",
    "review_none": "İncelenmedi",
    "f_candidates": "Bağlı adaylar",
    "f_poc": "PoC",
    "f_runtime": "Çalışma zamanı doğrulaması",
    "runtime_reproduced": "Tekrarlandı: PoC etkiyi sandbox'ta gösterdi",
    "runtime_inconclusive": "Sonuçsuz: PoC çalıştı ama etkiyi göstermedi",
    "runtime_not_performed": "Yapılmadı",
    "runtime_related_reproduced": "Aynı kök nedenli {ids} kaydının PoC'si etkiyi sandbox'ta "
    "gösterdi.",
    "f_fingerprint": "Fingerprint",
    "f_description": "Açıklama",
    "f_root_cause": "Kök neden",
    "f_claimed_root_cause": "İddia edilen kök neden",
    "f_intended": "Beklenen davranış",
    "f_trace": "Akış (trace)",
    "f_evidence": "Kanıt",
    "f_answers": "Üç soru",
    "f_conditions": "Koşullar",
    "f_execution": "Saldırı senaryosu",
    "f_attacker": "Saldırgan",
    "f_steps": "Adımlar",
    "f_payloads": "Payload",
    "f_observed": "Gözlenen sonuç",
    "f_poc_detail": "PoC sonucu",
    "f_poc_artifacts": "PoC dosyaları",
    "f_remediation": "Düzeltme",
    "f_code_change": "Kod değişikliği: {file}",
    "f_blockers": "Engeller",
    "f_validation_plan": "Doğrulama planı",
    "f_plan_local": "Yerel",
    "f_plan_deployment": "Dağıtım ortamı",
    "f_reason": "Red gerekçesi",
    "f_sca": "Bağımlılık",
    "col_step": "#",
    "col_kind": "Tür",
    "col_scope": "Kapsam",
    "col_description": "Açıklama",
    "col_question": "Soru",
    "col_answer": "Yanıt",
    "col_quotes": "Alıntılar",
    "not_translated": "(çevrilmedi)",
    "poc_none": "PoC kaydı yok",
    "poc_out_of_scope": "Bu analizi yapan kalkan sürümünde PoC sandbox yoktu. Bulgular, motorun "
    "doğruladığı statik kanıta dayanır.",
    "poc_sandbox_unavailable": "PoC doğrulama sandbox'ı bu analizde çalışmadı. Bulgular, "
    "motorun doğruladığı statik kanıta dayanır.",
    "blocker_sandbox_unavailable": "PoC doğrulama sandbox'ı çalışmadı (Docker kapalı veya "
    "erişilemedi).",
    "exec_limit_poc_unit": "PoC sandbox bu denetimde çalıştı. Etkiyi göstermeyen bir PoC açığın "
    "olmadığını kanıtlamaz.",
    "blocker_sandbox_timeout": "PoC verilen süre içinde bitmedi.",
    "blocker_sandbox_image_missing": "PoC temel imajı yüklü değil (kalkan sandbox pull).",
    "blocker_sandbox_app_deferred": "Bu denetimi yapan sürüm uygulama düzeyi PoC çalıştırmıyordu.",
    "blocker_sandbox_infeasible": "Ajan bu bulgu için sandbox'ta güvenle çalışan bir PoC "
    "yazamadı. Nedeni PoC sonucunda.",
    "blocker_sandbox_error": "PoC sandbox'ı bir hata ile durdu. Ayrıntı PoC sonucunda.",
    "blocker_agent_failed": "PoC ajanı bütün denemelerde kullanılabilir bir sonuç vermedi (örneğin "
    "bir güvenlik sınıflandırıcısı ajanı durdurdu). PoC yazılmadı.",
    "blocker_sandbox_image_not_allowed": "PoC izin listesinde olmayan bir temel imaj istedi.",
    "blocker_sandbox_output_limit": "PoC /out klasörüne sınırdan fazla yazdı. Motor konteyneri "
    "durdurdu.",
    "blocker_sandbox_app_unsafe": "Compose yığını güvenlik kurallarını geçmedi (örneğin "
    "privileged, host ağı veya hedef dışına bağlama). Motor yığını başlatmadı.",
    "blocker_sandbox_build_network_needed": "Yığın imaj derlemek istiyor ve derleme ağ ister. "
    "Denetimi --allow-build-network ile başlat.",
    # Consolidation (folded duplicates)
    "summary_duplicates": "{n} kayıt başka bir bulguyla aynı kök nedeni paylaşıyor. Sayılar bu "
    "kayıtları içermez. Liste ekte.",
    "f_related": "Aynı kök neden",
    "sub_duplicates": "Birleştirilen tekrar kayıtlar",
    "duplicates_intro": "Bu kayıtlar başka bir bulguyla aynı kök nedeni ve aynı düzeltmeyi "
    "paylaşıyor. Bir ajan bunu kaynaktan bir alıntıyla gösterdi. Motor alıntıyı doğruladı ve en "
    "güçlü kaydı birincil bulgu olarak seçti. Kayıtlar `findings.json` dosyasında duruyor. "
    "Sayılar onları ayrıca saymaz.",
    "col_primary": "Birincil bulgu",
    "exec_duplicates": "{n} tekrar kayıt, birincil bulgunun altına alındı. Sayılar bu kayıtları "
    "içermez.",
    # Hardening
    "hardening_intro": "Bu notlar zafiyet değil. Güvenliği artıran iyileştirmeler.",
    "hardening_none": "Hardening notu yok.",
    "hardening_missing": "Hardening notu yok: tamamlanmış hunt görevi yok.",
    "col_note": "Not",
    # Tool results
    "tool_results_intro": "Bu sonuçları deterministik araçlar üretti. Hiçbir ajan onları "
    "doğrulamadı. False positive içerebilir.",
    "tool_results_none": "Doğrulanmamış araç sonucu yok.",
    "tool_results_missing": "`candidates.json` yok. Araç sonuçları bilinmiyor.",
    "tool_results_truncated": "Bu motorun {n} sonucu daha var. Hepsi `candidates.json` içinde.",
    "col_rule": "Kural",
    "engine_counts": "{counts}",
    # SCA
    "sca_intro": "Bu kayıtlar bilinen zafiyetli bağımlılıkları gösterir. Ciddiyet, reachability "
    "sonucuna göre düşmüş olabilir.",
    "sca_none": "Bağımlılık zafiyeti yok.",
    "sca_missing": "`sca/vulns.json` yok. SCA sonucu bilinmiyor.",
    "sca_from_candidates": "`sca/vulns.json` yok. Tablo SCA adaylarından (`candidates.json`) "
    "geliyor.",
    "col_package": "Paket",
    "col_ecosystem": "Ekosistem",
    "col_vuln_ids": "Zafiyet ID",
    "col_fixed": "Düzeltilmiş sürüm",
    "col_reachability": "Reachability",
    "sca_unchecked": "{n} manifest dosyasında lockfile yok. SCA bu dosyaların yalnızca tam "
    "sürümlerini kontrol etti. Liste 2.6 bölümünde.",
    "sca_pin_note": "{n} kayıt, lockfile olmayan bir manifest dosyasındaki tam sürümden geliyor. "
    "Tablo bu kayıtları `manifest` etiketiyle gösterir.",
    "pin_label": "manifest",
    "pin_label_vendored": "gömülü",
    "sca_vendored_note": "{n} kayıt, projeye kopyalanmış (gömülü) JavaScript dosyalarından "
    "geliyor. Hiçbir paket yöneticisi bu dosyaları listelemiyor. Tablo bu kayıtları `gömülü` "
    "etiketiyle gösterir. Dosyalar:",
    "sca_sbom": "SBOM: {files}. {n} bileşen ({sources}).",
    "sca_malicious_title": "Zararlı bağımlılık",
    "sca_malicious_intro": "{n} paket sürümü bilinen zararlı paket kayıtlarıyla eşleşti (OSV "
    "`MAL-`, GitHub malware advisory). Zararlı kod paket kurulurken çalışır. Bu yüzden "
    "reachability sonucu önemli değil ve ciddiyet Kritik kalır.",
    "sca_malicious_actions": "Yapılacaklar:",
    "sca_malicious_action_1": "Paketi ve bu sürümü kaldır. Lockfile dosyasını yeniden üret.",
    "sca_malicious_action_2": "Paketi kuran her makineyi açığa çıkmış kabul et: geliştirici "
    "makineleri, CI runner'ları ve build imajları.",
    "sca_malicious_action_3": "Kurulumun okuyabildiği sırları değiştir (rotate): CI secret'ları, "
    "token'lar, bulut kimlik bilgileri ve SSH anahtarları.",
    "sca_malicious_action_4": "Lockfile geçmişinde bu sürümü ekleyen commit'i bul. Ondan sonraki "
    "build'leri kontrol et.",
    "sca_known_title": "Bilinen zafiyetler",
    "col_record_ids": "Kayıt ID",
    "sbom_source_syft": "Syft",
    "sbom_source_trivy": "Trivy",
    "sbom_source_sbom": "SBOM",
    "sbom_source_manifest_pin": "manifest sürümü",
    "sbom_source_vendored": "gömülü JavaScript",
    # Appendix
    "method_1": "kalkan her aday bulgu için üç soru sorar: saldırgan girdiyi kontrol ediyor mu, "
    "bir yetki sınırı aşılıyor mu, etkili bir önlem eksik mi.",
    "method_2": "Doğrulayıcı ajan her yanıtı kaynak koddan bir alıntıyla destekler.",
    "method_3": "Motor her alıntıyı kaynakta arar: belirtilen satır ile iki satır öncesi ve "
    "sonrası. Kaynakta olmayan alıntı sayılmaz.",
    "method_4": "Kararı ajan değil, motor verir. Üç soru kanıtlanırsa bulgu doğrulanır. Bir "
    "soru alıntıyla çürütülürse bulgu reddedilir. Diğer durumlarda bulgu doğrulama bekler.",
    "method_5": "PoC çalışmadıysa doğrulanan bulgu statik kanıta dayanır. Başarılı bir PoC güven "
    "seviyesini yükseltir. Doğrulayıcı gerekli alanları verdiyse, başarılı PoC doğrulama bekleyen "
    "bir bulguyu da doğrular.",
    "method_6": "Araç sonuçları ve SCA kayıtları deterministik motorlardan gelir. Ajan doğrulaması "
    "olmadan bulguya dönüşmez.",
    "tool_versions_missing": "`.tools/installed.json` yok. Araç sürümleri bilinmiyor.",
    "col_tool": "Araç",
    "col_kind_tool": "Kurulum",
    "run_kalkan_version": "kalkan sürümü",
    "run_report_files": "Rapor dosyaları",
    "warnings_title": "Uyarılar",
    "footer_static": "Statik denetim. Rapor kalkan motoru tarafından üretildi.",
    "english_hint": "İngilizce sürüm için önce `kalkan run answer english_report yes` komutunu "
    "çalıştır, sonra Claude Code'da `/kalkan devam` yaz.",
    # Executive summary page (EXECUTIVE.html)
    "exec_doc_title": "Yönetici özeti",
    "exec_subtitle": "Denetimin tek sayfalık özeti. Ayrıntılar tam raporda:",
    "exec_status_full": "Tam geçiş (full pass)",
    "exec_partial_fast": "fast profili, en çok {max} ajan görevi",
    "exec_partial_budget": "ajan görevi bütçesi doldu ({used} / {max})",
    "exec_partial_not_done": "çalıştırma bitmedi (son aşama: {phase})",
    "exec_partial_reason": "eksik kalma sebebi: {reason}",
    "exec_partial_unvalidated": "{n} hunter adayı doğrulanamadı",
    "exec_partial_ledger_open": "{n} kapsam birimi açık",
    "exec_partial_dead_tasks": "{n} ajan görevi başarısız oldu",
    "exec_partial_no_state": "`state.json` yok",
    "exec_partial_unchecked_manifests": "{n} manifest dosyasında lockfile yok",
    "exec_partial_database_gaps": "{n} SCA veritabanı boşluğu",
    "exec_partial_tools_only": "yalnızca araç modu: ajan doğrulaması yok",
    "exec_sec_risk": "Genel risk",
    "exec_posture_label": "Genel risk seviyesi",
    "exec_posture_unknown": "Bilinmiyor",
    "exec_posture_basis": "En yüksek doğrulanan ciddiyet: {label}.",
    "exec_posture_none": "Doğrulanan bulgu yok.",
    "exec_posture_missing": "`findings.json` yok. Seviye hesaplanamadı.",
    "exec_posture_tools_only": "Yalnızca araç modu (tools-only): hiçbir ajan bulgu doğrulamadı. "
    "Bu yüzden seviye hesaplanmadı.",
    "exec_posture_rule": "Kural: doğrulanan bir Kritik bulgu varsa seviye Kritik olur. Yoksa "
    "Yüksek bulgu varsa Yüksek, yoksa Orta bulgu varsa Orta olur. Diğer durumlarda seviye Düşük "
    "olur. Araç sonuçları ve SCA kayıtları seviyeyi değiştirmez.",
    "exec_posture_partial": "Kısmi geçiş: seviye yalnızca taranan kapsamı gösterir.",
    "exec_posture_sca": "Dikkat: {n} erişilebilir (reachable) bağımlılık paketinin ciddiyeti bu "
    "seviyenin üstünde. En yüksek ciddiyet: {label}. Ayrıntılar 4. bölümde.",
    "exec_posture_malicious": "Dikkat: bağımlılıklarda {n} bilinen zararlı paket sürümü var. "
    "Seviye kuralı SCA kayıtlarını saymaz, ama bu kayıtlar Kritik. Aşağıdaki kutuya bak.",
    "exec_malicious_title": "Zararlı bağımlılık: {n} paket sürümü",
    "exec_malicious_intro": "Bu sürümler bilinen zararlı paket kayıtlarıyla eşleşti (OSV "
    "`MAL-`, GitHub malware advisory). Zararlı kod kurulum sırasında çalışır, bu yüzden "
    "reachability önemli değil.",
    "exec_malicious_action": "Yapılacak: paketi kaldır, paketi kuran makineleri açığa çıkmış "
    "kabul et ve kurulumun okuyabildiği sırları değiştir. Adımlar tam raporun 8.1 bölümünde.",
    "exec_malicious_more": "Listede olmayan {n} zararlı paket sürümü daha var.",
    "exec_tiles_confirmed": "Doğrulanan bulgular: {n}",
    "exec_tiles_other": "Diğer kararlar",
    "exec_sec_top": "En önemli 10 bulgu",
    "exec_top_intro": "Doğrulanan bulgular önce ciddiyete, sonra olasılığa (likelihood) göre "
    "sıralı. Başlık, tam rapordaki bulguyu açar.",
    "exec_col_rank": "#",
    "exec_col_finding": "Bulgu",
    "exec_col_impact": "Etki",
    "exec_top_more": "Toplam {n} doğrulanan bulgu var. Hepsi tam raporun 3. bölümünde.",
    "exec_top_needs_validation": "{n} bulgu doğrulama bekliyor. Liste tam raporun 4. bölümünde.",
    "exec_top_missing": "`findings.json` yok. Bulgu listesi yok.",
    "exec_sec_classes": "Sınıflar ve bileşenler",
    "exec_sub_classes": "Sınıf ve ciddiyet",
    "exec_classes_intro": "Doğrulanan bulguların sayısı.",
    "exec_class_other": "Diğer sınıflar: {n}",
    "exec_class_none": "Sınıfı yok",
    "exec_sub_components": "Etkilenen bileşenler",
    "exec_components_intro": "Bileşen: dosya yolunun ilk iki klasörü.",
    "exec_col_component": "Bileşen",
    "exec_col_count": "Bulgu",
    "exec_col_highest": "En yüksek",
    "exec_root_folder": "(kök klasör)",
    "exec_components_more": "Listede olmayan {n} bileşen daha var.",
    "exec_sec_sca": "Bağımlılıklar (SCA)",
    "exec_sca_summary": "{packages} zafiyetli paket, {records} zafiyet kaydı.",
    "exec_sca_severity": "Ciddiyete göre paket",
    "exec_sca_reach": "Reachability (paket)",
    "exec_sca_top": "En önemli 5 paket",
    "exec_sca_no_fix": "Bilinen düzeltme yok",
    "exec_sca_fixed_in": "`{version}` veya üstü",
    "exec_sca_unfixed": "{n} kaydın bilinen düzeltmesi yok",
    "exec_sca_malicious": "{n} zararlı paket sürümü sayfanın başındaki kutuda. Bu bölüm onları "
    "saymaz.",
    "exec_col_unverified": "Doğrulanmamış sonuç",
    "exec_tools_sca": "SCA motorlarının sonuçları 4. bölümde.",
    "exec_sec_coverage": "Kapsam ve sınırlar",
    "exec_cov_budget": "Ajan görevi bütçesi",
    "exec_budget_value": "{used} / {max} kullanıldı",
    "exec_cov_ledger": "Kapsam defteri",
    "exec_ledger_value": "%{pct} kapandı ({closed} / {total} birim)",
    "exec_review_value": "{reviewed} kayıt incelendi: {verified} doğrulandı, {downgrade} "
    "düşürüldü, {reject} reddedildi.",
    "exec_review_fast": "fast profilinde ayrı bir son inceleme yok.",
    "f_deploy": "Kurulum",
    "f_run": "Çalıştırma",
    "exec_run_cost": "{type}. Takvim süresi {elapsed}, aktif süre {active} ({rounds} tur). "
    "Maliyet: {cost} USD (API eşdeğeri).",
    "exec_run_cost_api": "{type}. Takvim süresi {elapsed}, aktif süre {active} ({rounds} tur). "
    "Maliyet: {cost} USD, API hesabından ödendi ({auth}). Tutar, Claude Code'un liste fiyatıyla "
    "yaptığı tahmin. Kesin tutar sağlayıcının faturasında.",
    "exec_run_no_cost": "{type}. Takvim süresi {elapsed}. Maliyet kaydedilmedi: etkileşimli "
    "oturum veya yalnızca araç modu. Maliyet `kalkan-audit` ile kaydedilir.",
    "deploy_template_tag": "(yalnızca şablon)",
    "deploy_scope_live": "Canlı kurulumda",
    "deploy_scope_template": "Yalnızca şablon: canlıda çalışmayan bir kurulum dosyasında veya "
    "kodda. Genel riske katılmadı.",
    "exec_deploy_live": "Canlı kurulum: {live}. Yalnızca şablonda kalan {n} doğrulanmış bulgu "
    "genel riske katılmadı.",
    "exec_deploy_not_live": "Canlıda çalışmayan kod: {paths}.",
    "exec_deploy_template_n": "Yalnızca canlı dışı yerlerde kalan {n} doğrulanmış bulgu genel "
    "riske katılmadı.",
    "exec_deploy_unknown": "Repoda {n} kurulum tanımı var: {sets}. Hangisinin canlıda çalıştığı "
    "belirtilmedi, bu yüzden hepsi aynı ağırlıkta sayıldı. Belirtmek için: `kalkan run set "
    "--live <yol>`, sonra `kalkan report`.",
    "exec_gaps_none": "Tarama boşluğu yok.",
    "exec_gap_manifests": "{n} manifest dosyasında lockfile yok.",
    "exec_sca_unchecked": "{n} manifest dosyasında lockfile yok. Bu dosyalarda yalnızca tam "
    "sürümler kontrol edildi, dolaylı bağımlılıklar kontrol edilmedi. Liste tam raporun 2.6 "
    "bölümünde.",
    "exec_gap_databases": "{n} SCA veritabanı boşluğu var.",
    "exec_gap_partial": "`{engine}` {n} dosyayı kısmen analiz etti.",
    "exec_gap_skipped": "`{engine}` {n} dosyayı atladı.",
    "exec_gap_packages": "`{engine}` {n} Go paketini tam yükleyemedi.",
    "exec_gap_long_paths": "{n} dosyanın yolu çok uzun. Opengrep bu dosyaları atlayabilir.",
    "exec_gaps_detail": "Ayrıntılar tam raporun 2.6 bölümünde.",
    "exec_warnings": "{n} uyarı var. Liste tam raporun A.4 bölümünde.",
    "exec_cov_limits": "Sınırlar",
    "exec_limit_unverified": "Doğrulanmamış araç sonuçları ve SCA kayıtları bulgu sayılmaz.",
    "exec_cov_outputs": "Çıktılar",
    "exec_sec_actions": "Öncelikli aksiyonlar",
    "exec_actions_intro": "En önemli bulguların düzeltmeleri, önem sırasıyla.",
    "exec_actions_none": "Doğrulanan bulgu yok. Öncelikli aksiyon yok.",
    "exec_actions_sca": "Bağımlılık güncellemeleri 4. bölümde.",
    "exec_action_more": "+{n} bulgu",
    "exec_footer_full": "Tam rapor: {name}",
}

_EN: Final[dict[str, str]] = {
    "doc_title": "Security audit report",
    "doc_kicker": "SECURITY AUDIT",
    "doc_subtitle": "kalkan audit output: confirmed findings, tool results and coverage.",
    "contents": "Contents",
    "theme_toggle": "Theme",
    "lang_name": "English",
    "meta_field": "Field",
    "meta_value": "Value",
    "meta_run_id": "Run ID",
    "meta_target": "Target",
    "meta_target_kind": "Target kind",
    "meta_git_ref": "Git commit",
    "meta_profile": "Profile",
    "meta_lang": "Run language",
    "meta_created": "Started",
    "meta_updated": "Last update",
    "meta_generated": "Report date",
    "meta_phase": "Phase",
    "meta_status": "Status",
    "meta_tech": "Technologies",
    "kind_path": "Local folder",
    "kind_git": "Git repository",
    "status_complete": "Complete",
    "status_incomplete": "Incomplete",
    "status_unknown": "Unknown",
    "none": "None",
    "unknown": "Unknown",
    "dash": "—",
    "sec_summary": "Executive summary",
    "sec_scope": "Scope",
    "sec_confirmed": "Confirmed findings",
    "sec_needs_validation": "Findings that need validation",
    "sec_rejected": "Rejected findings",
    "sec_hardening": "Hardening notes",
    "sec_tool_results": "Tool results (unverified)",
    "sec_sca": "Vulnerable dependencies (SCA)",
    "sec_appendix": "Appendix A. Method and sources",
    "appendix_short": "App. A",
    "sub_profile_budget": "Profile and budget",
    "sub_phases": "Phases",
    "sub_engines": "Scanners",
    "sub_ledger": "Coverage ledger",
    "sub_missing": "Missing inputs",
    "sub_method": "Method",
    "sub_tool_versions": "Tool versions",
    "sub_run": "Run",
    "sub_findings_table": "Finding list",
    "sub_unvalidated": "Unvalidated candidates",
    "unvalidated_intro": "The validation budget ran out. No verify task ran for these hunter "
    "candidates. They are not findings. The coverage unit of each candidate stays open "
    "(`validation_budget_exhausted`).",
    "col_fingerprint": "Fingerprint",
    "col_suggested": "Suggested impact / likelihood",
    "col_units": "Coverage unit",
    "summary_confirmed": "Confirmed findings: {n}.",
    "summary_confirmed_none": "kalkan found no confirmed finding.",
    "summary_highest": "Highest severity: {label}.",
    "summary_needs_validation": "Findings that need validation: {n}.",
    "summary_rejected": "Candidate findings that the verifier rejected: {n}.",
    "summary_tool_results": "Unverified tool results: {n}.",
    "summary_sca": "Vulnerable dependencies (SCA): {n}. Reachable records: {reachable}.",
    "summary_malicious": "Warning: known malicious package versions in the dependencies: {n}. "
    "These packages run code when they are installed. Do the steps of section 8.1 now.",
    "summary_findings_missing": "`findings.json` is missing. The merge step did not run.",
    "summary_unvalidated": "Hunter candidates without validation (budget exhausted): {n}.",
    "summary_partial": "This report may not cover the whole target. Section 2 gives the reasons.",
    "kpi_confirmed": "Confirmed findings",
    "kpi_needs_validation": "Need validation",
    "kpi_rejected": "Rejected",
    "kpi_tool_results": "Unverified tool results",
    "kpi_sca": "SCA records",
    "kpi_sca_malicious": "Malicious dependencies",
    "kpi_severity_note": "The severity counts cover confirmed findings only.",
    "count_table_metric": "Metric",
    "count_table_count": "Count",
    "partial_title": "Partial pass",
    "partial_intro": "This report may not cover the whole target. Reasons:",
    "partial_full": "This run is complete. The coverage ledger has no open unit.",
    "partial_fast": "The `fast` profile was used. This profile runs at most {max} agent tasks.",
    "partial_budget": "The agent task budget is used up: {used} / {max}.",
    "partial_not_done": "The run did not finish. Last phase: {phase}.",
    "partial_reason": "The run is incomplete: {reason}",
    "partial_ledger_open": "Open coverage units (planned, in_progress, deferred or blocked): {n}.",
    "partial_dead_tasks": "Agent tasks that failed in every attempt: {n}.",
    "partial_unvalidated": "Hunter candidates without validation (budget exhausted): {n}. "
    "Section 1 lists them.",
    "partial_no_state": "`state.json` is missing. The run status is unknown.",
    "partial_unchecked_manifests": "Dependency manifests without a lockfile: {n}. SCA did not "
    "check their version ranges or transitive dependencies.",
    "partial_database_gaps": "SCA matching gaps: {n}. A local vulnerability database was "
    "missing. kalkan never asks an online service about the packages.",
    "partial_tools_only": "Tools-only mode: no agent validation. All results are unverified "
    "tool results.",
    "sub_gaps": "Scan gaps",
    "gaps_intro": "The tools could not scan these files completely. A file without results here "
    "is not necessarily clean.",
    "gaps_manifests": "These manifests have no lockfile next to them. The SCA tools read the "
    "package versions and the transitive dependencies from a lockfile. kalkan checked the exact "
    "versions (exact pins) of these manifests separately.",
    "gaps_databases": "These SCA tools had no local vulnerability database, so they did not check "
    "the packages below. kalkan sends no package name or version to an online service. Fix: "
    "`kalkan sca update-db`, then a new run.",
    "gaps_db_all": "all ecosystems",
    "gaps_partial": "{engine}: files analyzed only partially (parse errors or internal tool "
    "errors): {n}.",
    "gaps_skipped": "{engine}: files skipped: {n}.",
    "gaps_reasons": "Reasons",
    "gaps_files": "Files",
    "gaps_more": "Files not listed here: {n}.",
    "gaps_packages_gosec": "{engine}: Go packages loaded with errors: {n}. The checks that need "
    "type information or SSA did not run for them. The syntax checks ran.",
    "gaps_packages_govulncheck": "{engine}: Go packages that did not load: {n}. govulncheck did "
    "not check the reachability of the Go records.",
    "gaps_packages": "{engine}: Go packages loaded with errors: {n}.",
    "gaps_packages_more": "Packages not listed here: {n}.",
    "gaps_package_missing_local": "The module of {names} is not in the local module cache or a "
    "`vendor` folder. Local mode downloads no Go module (`GOPROXY=off`).",
    "gaps_package_missing_online": "The module of {names} could not be loaded.",
    "gaps_package_missing_import": "an imported package",
    "gaps_package_error": "Package load errors (syntax or type errors).",
    "gaps_packages_fix_gosec": "Fix: `kalkan scan gosec --online` (downloads the Go modules of "
    "the target) or a `vendor/` folder in the target. Both give gosec full type information.",
    "gaps_packages_fix_govulncheck": "Fix: `kalkan sca reach --online` (downloads the Go "
    "modules of the target) or a `vendor/` folder in the target.",
    "gaps_long_paths": "Files with an absolute path of {limit} or more characters: {n}. Opengrep "
    "may skip them without a warning. Cause: the Opengrep core program is not long-path aware. "
    "LongPathsEnabled=1 does not lift this limit.",
    "gaps_long_paths_registry": "LongPathsEnabled on this host: {value}.",
    "gaps_long_paths_fix": "Fix: set `KALKAN_RUNS_DIR` to a short folder (for example `C:/kr`). "
    "Then start a new run.",
    "value_on": "on",
    "value_off": "off",
    "col_file": "File",
    "col_exact_pins": "Exact pins checked",
    "col_ranges": "Ranges not checked",
    "reason_ranges": "Version ranges without a lockfile",
    "reason_pins_only": "Only exact pins. Transitive dependencies were not checked.",
    "reason_unreadable": "The file cannot be read",
    "scope_profile": "Profile: {profile}.",
    "scope_budget": "Agent task budget: {used} / {max} used.",
    "scope_budget_missing": "No budget data.",
    "col_phase": "Phase",
    "col_status": "Status",
    "col_started": "Started",
    "col_finished": "Finished",
    "col_engine": "Engine",
    "col_group": "Group",
    "col_version": "Version",
    "col_duration": "Duration",
    "col_message": "Note",
    "col_ledger_status": "Unit status",
    "col_count": "Count",
    "col_total": "Total",
    "phases_missing": "No phase data (`state.json` could not be read).",
    "engines_missing": "No scanner status file (`scans/*.status.json`, `sca/*.status.json`).",
    "ledger_missing": "`coverage-ledger.json` is missing. The number of coverage units is unknown.",
    "ledger_empty": "The coverage ledger has no unit.",
    "ledger_sibling_closed": "Blocked units that the critic closed from sibling coverage: {n}. "
    "The sibling units read the code that settles the missing facts. The engine checked every "
    "quote against the source. The table counts these units as Covered.",
    "review_counts": "{reviewed} records passed a second, independent review: {verified} "
    "verified, {downgrade} downgraded, {reject} rejected. Confirmed or needs-validation records "
    "without a review: {not_reviewed}.",
    "review_fast": "The fast profile has no separate final review. The verify task also does "
    "the record checks (Cloudflare quick profile).",
    "missing_intro": "These inputs are missing or unreadable. The report shows only the data "
    "that exists.",
    "missing_none": "All inputs were read.",
    "group_scans": "Scan",
    "group_sca": "SCA",
    "seconds": "{s} s",
    "findings_none_confirmed": "No confirmed finding.",
    "findings_none_needs_validation": "No finding needs validation.",
    "findings_none_rejected": "No rejected finding.",
    "confirmed_intro": "The engine confirms a finding in one of two ways: the three questions "
    "are established with quotes that the engine found in the source, or a sandbox PoC "
    "demonstrates the vulnerability. The findings are ordered by severity.",
    "needs_validation_intro": "The evidence for these findings is incomplete. They have no "
    "severity. Read the blockers and the validation plan.",
    "rejected_intro": "The verifier or the final review rejected these candidates. The records "
    "stay for the audit trail.",
    "translation_scope": "kalkan translates the title, the description and the remediation of "
    "each finding. Other fields keep the language of the run.",
    "col_id": "ID",
    "col_title": "Title",
    "col_severity": "Severity",
    "col_verdict": "Verdict",
    "col_class": "Class",
    "col_location": "Location",
    "col_reason": "Reason",
    "col_poc": "PoC",
    "f_id": "ID",
    "f_severity": "Severity",
    "f_severity_detail": "{overall} (likelihood: {likelihood}, impact: {impact})",
    "f_cvss": "CVSS",
    "f_confidence": "Confidence",
    "f_class": "Class",
    "f_cwe": "CWE",
    "f_owasp": "OWASP",
    "f_location": "Location",
    "f_engines": "Engines",
    "f_review": "Final review",
    "review_none": "Not reviewed",
    "f_candidates": "Linked candidates",
    "f_poc": "PoC",
    "f_runtime": "Runtime validation",
    "runtime_reproduced": "Reproduced: the PoC showed the effect in the sandbox",
    "runtime_inconclusive": "Inconclusive: the PoC ran but did not show the effect",
    "runtime_not_performed": "Not performed",
    "runtime_related_reproduced": "The PoC of {ids}, a record with the same root cause, showed "
    "the effect in the sandbox.",
    "f_fingerprint": "Fingerprint",
    "f_description": "Description",
    "f_root_cause": "Root cause",
    "f_claimed_root_cause": "Claimed root cause",
    "f_intended": "Intended behavior",
    "f_trace": "Trace",
    "f_evidence": "Evidence",
    "f_answers": "Three questions",
    "f_conditions": "Conditions",
    "f_execution": "Attack scenario",
    "f_attacker": "Attacker",
    "f_steps": "Steps",
    "f_payloads": "Payload",
    "f_observed": "Observed result",
    "f_poc_detail": "PoC result",
    "f_poc_artifacts": "PoC files",
    "f_remediation": "Remediation",
    "f_code_change": "Code change: {file}",
    "f_blockers": "Blockers",
    "f_validation_plan": "Validation plan",
    "f_plan_local": "Local",
    "f_plan_deployment": "Deployment",
    "f_reason": "Rejection reason",
    "f_sca": "Dependency",
    "col_step": "#",
    "col_kind": "Kind",
    "col_scope": "Scope",
    "col_description": "Description",
    "col_question": "Question",
    "col_answer": "Answer",
    "col_quotes": "Quotes",
    "not_translated": "(not translated)",
    "poc_none": "No PoC record",
    "poc_out_of_scope": "The kalkan version that made this audit had no PoC sandbox. The "
    "findings rest on engine-verified static evidence.",
    "poc_sandbox_unavailable": "The PoC verification sandbox did not run in this audit. The "
    "findings rest on engine-verified static evidence.",
    "blocker_sandbox_unavailable": "The PoC verification sandbox did not run (Docker was off "
    "or not available).",
    "exec_limit_poc_unit": "The PoC sandbox ran in this audit. A PoC that does not show the effect "
    "does not prove that the flaw is absent.",
    "blocker_sandbox_timeout": "The PoC did not finish within the time limit.",
    "blocker_sandbox_image_missing": "The PoC base image is not installed (kalkan sandbox pull).",
    "blocker_sandbox_app_deferred": "The version that made this audit did not run app-level PoCs.",
    "blocker_sandbox_infeasible": "The agent could not write a PoC that runs safely in the "
    "sandbox for this finding. The PoC result names the reason.",
    "blocker_agent_failed": "The PoC agent gave no usable result in any attempt (for example, a "
    "safety classifier stopped the agent). No PoC was written.",
    "blocker_sandbox_error": "The PoC sandbox stopped with an error. The PoC result has the "
    "details.",
    "blocker_sandbox_image_not_allowed": "The PoC asked for a base image that is not in the "
    "allowlist.",
    "blocker_sandbox_output_limit": "The PoC wrote more than the limit into /out. The engine "
    "stopped the container.",
    "blocker_sandbox_app_unsafe": "The compose stack failed the safety rules (for example "
    "privileged mode, the host network or a mount outside the target). The engine did not start "
    "it.",
    "blocker_sandbox_build_network_needed": "The stack builds images, and a build needs the "
    "network. Start the audit with --allow-build-network.",
    "summary_duplicates": "Records that share the root cause of another finding: {n}. The "
    "counts leave them out; the appendix lists them.",
    "f_related": "Same root cause",
    "sub_duplicates": "Folded duplicate records",
    "duplicates_intro": "These records share the root cause and the fix of another finding. An "
    "agent showed it with a quote from the source. The engine checked the quote and chose the "
    "strongest record as the primary finding. The records stay in `findings.json`. The counts "
    "leave them out.",
    "col_primary": "Primary finding",
    "exec_duplicates": "Duplicate records folded into their primary findings: {n}. The counts "
    "leave them out.",
    "hardening_intro": "These notes are not vulnerabilities. They are improvements that raise "
    "security.",
    "hardening_none": "No hardening note.",
    "hardening_missing": "No hardening note: no hunt task is done.",
    "col_note": "Note",
    "tool_results_intro": "Deterministic tools produced these results. No agent verified them. "
    "They can contain false positives.",
    "tool_results_none": "No unverified tool result.",
    "tool_results_missing": "`candidates.json` is missing. The tool results are unknown.",
    "tool_results_truncated": "More results of this engine: {n}. All of them are in "
    "`candidates.json`.",
    "col_rule": "Rule",
    "engine_counts": "{counts}",
    "sca_intro": "These records show known vulnerable dependencies. The reachability result can "
    "lower the severity.",
    "sca_none": "No vulnerable dependency.",
    "sca_missing": "`sca/vulns.json` is missing. The SCA result is unknown.",
    "sca_from_candidates": "`sca/vulns.json` is missing. The table comes from the SCA "
    "candidates (`candidates.json`).",
    "col_package": "Package",
    "col_ecosystem": "Ecosystem",
    "col_vuln_ids": "Vulnerability ID",
    "col_fixed": "Fixed version",
    "col_reachability": "Reachability",
    "sca_unchecked": "Manifests without a lockfile: {n}. SCA checked only their exact pins. "
    "Section 2.6 lists them.",
    "sca_pin_note": "Records from an exact pin in a manifest without a lockfile: {n}. The table "
    "marks them with `manifest`.",
    "pin_label": "manifest",
    "pin_label_vendored": "vendored",
    "sca_vendored_note": "Records from JavaScript files that the project copied into its tree "
    "(vendored): {n}. No package manager lists these files. The table marks the records with "
    "`vendored`. Files:",
    "sca_sbom": "SBOM: {files}. Components: {n} ({sources}).",
    "sca_malicious_title": "Malicious dependency",
    "sca_malicious_intro": "Package versions that match a known malicious package record (OSV "
    "`MAL-`, GitHub malware advisory): {n}. The malicious code runs when the package is "
    "installed. Thus the reachability result does not matter, and the severity stays Critical.",
    "sca_malicious_actions": "Do these steps:",
    "sca_malicious_action_1": "Remove the package and this version. Regenerate the lockfile.",
    "sca_malicious_action_2": "Treat every machine that installed the package as exposed: "
    "developer machines, CI runners and build images.",
    "sca_malicious_action_3": "Rotate the secrets that the install could read: CI secrets, "
    "tokens, cloud credentials and SSH keys.",
    "sca_malicious_action_4": "Find the commit that added this version in the lockfile history. "
    "Check the builds after it.",
    "sca_known_title": "Known vulnerabilities",
    "col_record_ids": "Record IDs",
    "sbom_source_syft": "Syft",
    "sbom_source_trivy": "Trivy",
    "sbom_source_sbom": "SBOM",
    "sbom_source_manifest_pin": "manifest pin",
    "sbom_source_vendored": "vendored JavaScript",
    "method_1": "For each candidate finding, kalkan asks three questions: does the attacker "
    "control the input, does the flow cross a privilege boundary, is an effective mitigation "
    "missing.",
    "method_2": "The verifier agent supports each answer with a quote from the source code.",
    "method_3": "The engine looks for each quote in the source: the cited line and two lines "
    "before and after it. A quote that is not in the source does not count.",
    "method_4": "The engine, not the agent, gives the verdict. Three established answers confirm "
    "the finding. One answer refuted with a quote rejects it. Otherwise the finding needs "
    "validation.",
    "method_5": "Without a PoC run, a confirmed finding rests on static evidence. A passed PoC "
    "raises the confidence. When the verifier supplied the required fields, a passed PoC also "
    "confirms a finding that needs validation.",
    "method_6": "Tool results and SCA records come from deterministic engines. They do not "
    "become findings without agent verification.",
    "tool_versions_missing": "`.tools/installed.json` is missing. The tool versions are unknown.",
    "col_tool": "Tool",
    "col_kind_tool": "Install kind",
    "run_kalkan_version": "kalkan version",
    "run_report_files": "Report files",
    "warnings_title": "Warnings",
    "footer_static": "Static audit. The kalkan engine produced this report.",
    "english_hint": "The Turkish version of this report is `REPORT.md`.",
    "exec_doc_title": "Executive summary",
    "exec_subtitle": "A one-page summary of the audit. The full report has the details:",
    "exec_status_full": "Full pass",
    "exec_partial_fast": "fast profile (at most {max} agent tasks)",
    "exec_partial_budget": "agent task budget used up ({used} / {max})",
    "exec_partial_not_done": "run not finished (last phase: {phase})",
    "exec_partial_reason": "incomplete: {reason}",
    "exec_partial_unvalidated": "hunter candidates without validation: {n}",
    "exec_partial_ledger_open": "open coverage units: {n}",
    "exec_partial_dead_tasks": "failed agent tasks: {n}",
    "exec_partial_no_state": "`state.json` is missing",
    "exec_partial_unchecked_manifests": "manifests without a lockfile: {n}",
    "exec_partial_database_gaps": "SCA database gaps: {n}",
    "exec_partial_tools_only": "tools-only mode: no agent validation",
    "exec_sec_risk": "Overall risk",
    "exec_posture_label": "Overall risk level",
    "exec_posture_unknown": "Unknown",
    "exec_posture_basis": "Highest confirmed severity: {label}.",
    "exec_posture_none": "No confirmed finding.",
    "exec_posture_missing": "`findings.json` is missing. The level cannot be computed.",
    "exec_posture_tools_only": "Tools-only mode: no agent validated a finding, so the level "
    "was not computed.",
    "exec_posture_rule": "Rule: a confirmed Critical finding makes the level Critical. Else a "
    "High finding makes it High, else a Medium finding makes it Medium. Otherwise the level is "
    "Low. Tool results and SCA records do not change the level.",
    "exec_posture_partial": "Partial pass: the level covers only the scanned scope.",
    "exec_posture_sca": "Note: reachable dependency packages with a severity above this level: "
    "{n}. Highest severity: {label}. Section 4 has the details.",
    "exec_posture_malicious": "Warning: known malicious package versions in the dependencies: "
    "{n}. The level rule does not count SCA records, but these records are Critical. See the box "
    "below.",
    "exec_malicious_title": "Malicious dependencies: {n}",
    "exec_malicious_intro": "These versions match a known malicious package record (OSV "
    "`MAL-`, GitHub malware advisory). The malicious code runs at install time, so reachability "
    "does not matter.",
    "exec_malicious_action": "Action: remove the package, treat the machines that installed it "
    "as exposed and rotate the secrets that the install could read. Section 8.1 of the full "
    "report has the steps.",
    "exec_malicious_more": "Malicious package versions not listed here: {n}.",
    "exec_tiles_confirmed": "Confirmed findings: {n}",
    "exec_tiles_other": "Other verdicts",
    "exec_sec_top": "Top 10 findings",
    "exec_top_intro": "Confirmed findings, ordered by severity, then likelihood. A title opens "
    "the finding in the full report.",
    "exec_col_rank": "#",
    "exec_col_finding": "Finding",
    "exec_col_impact": "Impact",
    "exec_top_more": "Confirmed findings in total: {n}. Section 3 of the full report lists all "
    "of them.",
    "exec_top_needs_validation": "Findings that need validation: {n}. Section 4 of the full "
    "report lists them.",
    "exec_top_missing": "`findings.json` is missing. There is no finding list.",
    "exec_sec_classes": "Classes and components",
    "exec_sub_classes": "Class and severity",
    "exec_classes_intro": "Number of confirmed findings.",
    "exec_class_other": "Other classes: {n}",
    "exec_class_none": "No class",
    "exec_sub_components": "Affected components",
    "exec_components_intro": "Component: the first two folders of the file path.",
    "exec_col_component": "Component",
    "exec_col_count": "Findings",
    "exec_col_highest": "Highest",
    "exec_root_folder": "(root folder)",
    "exec_components_more": "Components not listed here: {n}.",
    "exec_sec_sca": "Dependencies (SCA)",
    "exec_sca_summary": "Vulnerable packages: {packages}. Vulnerability records: {records}.",
    "exec_sca_severity": "Packages by severity",
    "exec_sca_reach": "Reachability (packages)",
    "exec_sca_top": "Top 5 packages",
    "exec_sca_no_fix": "No known fix",
    "exec_sca_fixed_in": "`{version}` or later",
    "exec_sca_unfixed": "Records without a known fix: {n}",
    "exec_sca_malicious": "Malicious package versions: {n}. They are in the box at the top of "
    "the page, not in this section.",
    "exec_col_unverified": "Unverified results",
    "exec_tools_sca": "Section 4 shows the results of the SCA engines.",
    "exec_sec_coverage": "Coverage and limits",
    "exec_cov_budget": "Agent task budget",
    "exec_budget_value": "{used} / {max} used",
    "exec_cov_ledger": "Coverage ledger",
    "exec_ledger_value": "{pct}% closed ({closed} / {total} units)",
    "exec_review_value": "Records reviewed: {reviewed} ({verified} verified, {downgrade} "
    "downgraded, {reject} rejected).",
    "exec_review_fast": "The fast profile has no separate final review.",
    "f_deploy": "Deployment",
    "f_run": "Run",
    "exec_run_cost": "{type}. Calendar time {elapsed}, active time {active} ({rounds} rounds). "
    "Cost: USD {cost} (API-equivalent).",
    "exec_run_cost_api": "{type}. Calendar time {elapsed}, active time {active} ({rounds} "
    "rounds). Cost: USD {cost}, billed to an API account ({auth}). The amount is the estimate of "
    "Claude Code at list prices; the bill of the provider is the authority.",
    "exec_run_no_cost": "{type}. Calendar time {elapsed}. Cost not recorded: an interactive "
    "session or a tools-only run. `kalkan-audit` records the cost.",
    "deploy_template_tag": "(template only)",
    "deploy_scope_live": "In the live deployment",
    "deploy_scope_template": "Template only: in a deployment file or in code that does not run "
    "in production. Left out of the overall risk.",
    "exec_deploy_live": "Live deployment: {live}. Confirmed findings only in templates, left out "
    "of the overall risk: {n}.",
    "exec_deploy_not_live": "Code that production does not load: {paths}.",
    "exec_deploy_template_n": "Confirmed findings only outside production, left out of the "
    "overall risk: {n}.",
    "exec_deploy_unknown": "The repository holds {n} deployment descriptions: {sets}. Nobody named "
    "the one that runs in production, so all of them count the same. To name it: `kalkan run "
    "set --live <path>`, then `kalkan report`.",
    "exec_gaps_none": "No scan gap.",
    "exec_gap_manifests": "Manifests without a lockfile: {n}.",
    "exec_sca_unchecked": "Manifests without a lockfile: {n}. Only their exact versions were "
    "checked, not their transitive dependencies. Section 2.6 of the full report lists them.",
    "exec_gap_databases": "SCA database gaps: {n}.",
    "exec_gap_partial": "`{engine}`: files analyzed only partially: {n}.",
    "exec_gap_skipped": "`{engine}`: files skipped: {n}.",
    "exec_gap_packages": "`{engine}`: Go packages not fully loaded: {n}.",
    "exec_gap_long_paths": "Files with a very long path: {n}. Opengrep may skip them.",
    "exec_gaps_detail": "Section 2.6 of the full report has the details.",
    "exec_warnings": "Warnings: {n}. Section A.4 of the full report lists them.",
    "exec_cov_limits": "Limits",
    "exec_limit_unverified": "Unverified tool results and SCA records do not count as findings.",
    "exec_cov_outputs": "Outputs",
    "exec_sec_actions": "Priority actions",
    "exec_actions_intro": "The remediations of the top findings, in order of importance.",
    "exec_actions_none": "No confirmed finding. No priority action.",
    "exec_actions_sca": "Section 4 lists the dependency upgrades.",
    "exec_action_more": "+{n} more",
    "exec_footer_full": "Full report: {name}",
}

STRINGS: Final[dict[str, dict[str, str]]] = {"tr": _TR, "en": _EN}

_SEVERITY: Final = {
    "tr": {
        "critical": "Kritik",
        "high": "Yüksek",
        "medium": "Orta",
        "low": "Düşük",
        "info": "Bilgi",
    },
    "en": {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    },
}
_VERDICT: Final = {
    "tr": {
        "confirmed": "Doğrulandı",
        "needs_validation": "Doğrulama gerekiyor",
        "rejected": "Reddedildi",
    },
    "en": {
        "confirmed": "Confirmed",
        "needs_validation": "Needs validation",
        "rejected": "Rejected",
    },
}
_POC_STATUS: Final = {
    "tr": {
        "passed": "Başarılı",
        "failed": "Başarısız",
        "blocked": "Engellendi",
        "not_run": "Çalışmadı",
    },
    "en": {"passed": "Passed", "failed": "Failed", "blocked": "Blocked", "not_run": "Not run"},
}
_POC_LEVEL: Final = {
    "tr": {"unit": "birim (unit)", "app": "uygulama (app)"},
    "en": {"unit": "unit", "app": "app"},
}
_REACHABILITY: Final = {
    "tr": {"reachable": "Erişilebilir", "not_reachable": "Erişilemiyor", "unknown": "Bilinmiyor"},
    "en": {"reachable": "Reachable", "not_reachable": "Not reachable", "unknown": "Unknown"},
}
_ENGINE_STATUS: Final = {
    "tr": {
        "ok": "Çalıştı",
        "skipped": "Atlandı",
        "failed": "Başarısız",
        "timeout": "Zaman aşımı",
        "unknown": "Bilinmiyor",
    },
    "en": {
        "ok": "Ran",
        "skipped": "Skipped",
        "failed": "Failed",
        "timeout": "Timed out",
        "unknown": "Unknown",
    },
}
_PHASE: Final = {
    "tr": {
        "prep": "Hazırlık",
        "deterministic": "Deterministik tarama",
        "sca": "SCA",
        "recon": "Keşif (recon)",
        "plan": "Plan",
        "hunt": "Avlanma (hunt)",
        "validate": "Doğrulama",
        "poc": "PoC",
        "merge": "Birleştirme (merge)",
        "report": "Rapor",
        "done": "Bitti",
    },
    "en": {
        "prep": "Preparation",
        "deterministic": "Deterministic scan",
        "sca": "SCA",
        "recon": "Reconnaissance",
        "plan": "Plan",
        "hunt": "Hunt",
        "validate": "Validation",
        "poc": "PoC",
        "merge": "Merge",
        "report": "Report",
        "done": "Done",
    },
}
_PHASE_STATUS: Final = {
    "tr": {
        "pending": "Bekliyor",
        "running": "Sürüyor",
        "done": "Bitti",
        "skipped": "Atlandı",
        "failed": "Başarısız",
    },
    "en": {
        "pending": "Pending",
        "running": "Running",
        "done": "Done",
        "skipped": "Skipped",
        "failed": "Failed",
    },
}
_LEDGER_STATUS: Final = {
    "tr": {
        "planned": "Planlandı (planned)",
        "not_applicable": "Uygulanamaz (not_applicable)",
        "out_of_scope": "Kapsam dışı (out_of_scope)",
        "in_progress": "Sürüyor (in_progress)",
        "covered": "İncelendi (covered)",
        "candidate": "Aday bulgu var (candidate)",
        "blocked": "Engellendi (blocked)",
        "deferred": "Ertelendi (deferred)",
    },
    "en": {
        "planned": "Planned",
        "not_applicable": "Not applicable",
        "out_of_scope": "Out of scope",
        "in_progress": "In progress",
        "covered": "Covered",
        "candidate": "Candidate found",
        "blocked": "Blocked",
        "deferred": "Deferred",
    },
}
_REVIEW: Final = {
    "tr": {"verified": "Doğrulandı", "downgrade": "Düşürüldü", "reject": "Reddedildi"},
    "en": {"verified": "Verified", "downgrade": "Downgraded", "reject": "Rejected"},
}
_CONFIDENCE: Final = {
    "tr": {"high": "Yüksek", "medium": "Orta", "low": "Düşük"},
    "en": {"high": "High", "medium": "Medium", "low": "Low"},
}
_PROFILE: Final = {
    "tr": {"fast": "fast", "standard": "standard", "deep": "deep"},
    "en": {"fast": "fast", "standard": "standard", "deep": "deep"},
}
_TRACE_KIND: Final = {
    "tr": {"entrypoint": "Giriş (entrypoint)", "propagation": "Aktarım", "sink": "Sink"},
    "en": {"entrypoint": "Entrypoint", "propagation": "Propagation", "sink": "Sink"},
}
_QUESTION: Final = {
    "tr": {
        "attacker_control": "Saldırgan girdiyi kontrol ediyor mu?",
        "privilege_boundary": "Bir yetki sınırı aşılıyor mu?",
        "unmitigated": "Etkili bir önlem eksik mi?",
    },
    "en": {
        "attacker_control": "Does the attacker control the input?",
        "privilege_boundary": "Does the flow cross a privilege boundary?",
        "unmitigated": "Is an effective mitigation missing?",
    },
}
_ANSWER: Final = {
    "tr": {"established": "Kanıtlandı", "refuted": "Çürütüldü", "unknown": "Bilinmiyor"},
    "en": {"established": "Established", "refuted": "Refuted", "unknown": "Unknown"},
}
_CONDITION: Final = {
    "tr": {
        "authentication_level": "Kimlik doğrulama seviyesi",
        "authorization_role": "Yetki rolü",
        "user_interaction": "Kullanıcı etkileşimi",
        "system_configuration": "Sistem yapılandırması",
        "network_routing": "Ağ yönlendirmesi",
        "environmental_dependency": "Ortam bağımlılığı",
        "data_state": "Veri durumu",
        "timing_dependency": "Zamanlama",
        "third_party_dependency": "Üçüncü taraf bağımlılığı",
    },
    "en": {
        "authentication_level": "Authentication level",
        "authorization_role": "Authorization role",
        "user_interaction": "User interaction",
        "system_configuration": "System configuration",
        "network_routing": "Network routing",
        "environmental_dependency": "Environmental dependency",
        "data_state": "Data state",
        "timing_dependency": "Timing dependency",
        "third_party_dependency": "Third-party dependency",
    },
}


def _lang(lang: str) -> str:
    return lang if lang in LANGUAGES else "tr"


def t(lang: str, key: str, **values: object) -> str:
    """Return the UI string ``key`` in ``lang`` (``tr`` or ``en``), formatted with ``values``.

    An unknown language falls back to Turkish. An unknown key raises ``KeyError``, so that a typo
    fails in the tests and never reaches a report.
    """
    text = STRINGS[_lang(lang)][key]
    return text.format(**values) if values else text


def poc_observed(lang: str, text: object) -> object:
    """Return the report text of a PoC ``observed_result`` in the report language.

    A skipped PoC (the ``sandbox_unavailable`` key) reads as "the sandbox did not run", and the
    scope statement of a run before 1.7.0 (:data:`POC_OUT_OF_SCOPE`, ADR-0004) reads as "that
    version had no sandbox". Any other text is returned as it is."""
    from kalkan.findings.merge import BLOCKER_SANDBOX_UNAVAILABLE, POC_OUT_OF_SCOPE

    if isinstance(text, str) and text.strip() == POC_OUT_OF_SCOPE:
        return t(lang, "poc_out_of_scope")
    if isinstance(text, str) and text.strip() == BLOCKER_SANDBOX_UNAVAILABLE:
        return t(lang, "poc_sandbox_unavailable")
    return text


#: The keys of the Go package gap line and its fix, per engine (``partial_packages``).
_PACKAGE_KEYS: Final = {
    "gosec": ("gaps_packages_gosec", "gaps_packages_fix_gosec"),
    "govulncheck": ("gaps_packages_govulncheck", "gaps_packages_fix_govulncheck"),
}


def package_gap_keys(engine: str) -> tuple[str, str | None]:
    """Return the keys of the package gap line and of its fix (None: no fix text)."""
    return _PACKAGE_KEYS.get(engine, ("gaps_packages", None))


def package_reason(lang: str, missing_imports: tuple[str, ...], local: bool) -> str:
    """Return why a Go package of a scan gap loaded with errors, in the report language."""
    if not missing_imports:
        return t(lang, "gaps_package_error")
    key = "gaps_package_missing_local" if local else "gaps_package_missing_online"
    return t(lang, key, names=", ".join(missing_imports))


_BLOCKER_KEYS: Final = {
    "sandbox_unavailable": "blocker_sandbox_unavailable",
    "sandbox_timeout": "blocker_sandbox_timeout",
    "sandbox_image_missing": "blocker_sandbox_image_missing",
    "sandbox_app_deferred": "blocker_sandbox_app_deferred",
    "sandbox_infeasible": "blocker_sandbox_infeasible",
    "sandbox_error": "blocker_sandbox_error",
    "agent_failed": "blocker_agent_failed",
    "sandbox_image_not_allowed": "blocker_sandbox_image_not_allowed",
    "sandbox_output_limit": "blocker_sandbox_output_limit",
    "sandbox_app_unsafe": "blocker_sandbox_app_unsafe",
    "sandbox_build_network_needed": "blocker_sandbox_build_network_needed",
}

_RUNTIME_KEYS: Final = {"passed": "runtime_reproduced", "failed": "runtime_inconclusive"}


def runtime_validation(lang: str, poc: object, related: object = None) -> str:
    """Return the runtime validation of a finding: reproduced, inconclusive or not performed.

    A passed PoC reproduced the effect and a failed PoC ran without it. A finding without a
    PoC run (no record, ``blocked`` or ``not_run``) had no runtime validation; the blocker note
    then says why. When the finding's own PoC did not pass, a folded record of the same root
    cause (``related`` with ``poc_status`` passed) adds a note with its ID.
    """
    status = poc.get("status") if isinstance(poc, Mapping) else None
    if status == "passed":
        return t(lang, _RUNTIME_KEYS[status])
    if status in _RUNTIME_KEYS:
        text = t(lang, _RUNTIME_KEYS[status])
    else:
        text = t(lang, "runtime_not_performed")
        note = blocker_note(lang, poc.get("blocker")) if isinstance(poc, Mapping) else None
        text = f"{text}. {note}" if note else text
    items = related if isinstance(related, list) else []
    passed = [
        item["id"]
        for item in items
        if isinstance(item, Mapping)
        and item.get("poc_status") == "passed"
        and isinstance(item.get("id"), str)
    ]
    if passed:
        text = f"{text}. {t(lang, 'runtime_related_reproduced', ids=', '.join(passed))}"
    return text


def blocker_note(lang: str, blocker: object) -> str | None:
    """Return the explanation of a known blocker code in the report language, or None."""
    key = _BLOCKER_KEYS.get(blocker) if isinstance(blocker, str) else None
    return t(lang, key) if key else None


def _label(table: dict[str, dict[str, str]], lang: str, value: object) -> str:
    if not isinstance(value, str):
        return ""
    return table[_lang(lang)].get(value, value)


def severity_label(lang: str, severity: object) -> str:
    """Kritik, Yüksek, Orta, Düşük, Bilgi (``informational`` maps to Bilgi)."""
    if severity == "informational":
        severity = "info"
    return _label(_SEVERITY, lang, severity)


def verdict_label(lang: str, verdict: object) -> str:
    return _label(_VERDICT, lang, verdict)


def poc_status_label(lang: str, status: object) -> str:
    return _label(_POC_STATUS, lang, status)


def poc_level_label(lang: str, level: object) -> str:
    return _label(_POC_LEVEL, lang, level)


def reachability_label(lang: str, value: object) -> str:
    return _label(_REACHABILITY, lang, value)


def engine_status_label(lang: str, status: object) -> str:
    return _label(_ENGINE_STATUS, lang, status)


def sbom_source_label(lang: str, source: object) -> str:
    """Return the label of an SBOM component source (``kalkan.report.sbom.SOURCE_ORDER``)."""
    key = f"sbom_source_{str(source).replace('-', '_')}"
    return t(lang, key) if key in STRINGS["en"] else str(source)


def phase_label(lang: str, phase: object) -> str:
    return _label(_PHASE, lang, phase)


def phase_status_label(lang: str, status: object) -> str:
    return _label(_PHASE_STATUS, lang, status)


def ledger_status_label(lang: str, status: object) -> str:
    return _label(_LEDGER_STATUS, lang, status)


def review_label(lang: str, decision: object) -> str:
    """Doğrulandı, Düşürüldü, Reddedildi (the decision of the final review)."""
    return _label(_REVIEW, lang, decision)


def confidence_label(lang: str, value: object) -> str:
    return _label(_CONFIDENCE, lang, value)


def profile_label(lang: str, profile: object) -> str:
    return _label(_PROFILE, lang, profile)


def trace_kind_label(lang: str, kind: object) -> str:
    return _label(_TRACE_KIND, lang, kind)


def question_label(lang: str, question: object) -> str:
    return _label(_QUESTION, lang, question)


def answer_label(lang: str, status: object) -> str:
    return _label(_ANSWER, lang, status)


def condition_label(lang: str, kind: object) -> str:
    return _label(_CONDITION, lang, kind)
