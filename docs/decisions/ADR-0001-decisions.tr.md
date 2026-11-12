# ADR-0001: Kalkan'ın temel kararları
[English](ADR-0001-decisions.md) | Türkçe

- **Durum:** Kabul edildi. Sonraki kararlar bazı satırları değiştirdi: faz kapıları ADR-0002, "PoC" satırı ADR-0004, ADR-0006 ve ADR-0008 (birim düzeyi ve uygulama düzeyi etkin), "Ek tarayıcılar" satırı ADR-0005.
- **Tarih:** 2026-10-15
- **Karar veren:** proje sahibi
- **Kaynaklar:** beş açık kaynak AI güvenlik aracının karşılaştırmalı analizi (aşağıdaki bağlama bak)

## Bağlam

Beş açık kaynak AI güvenlik aracını inceledik: sast-skills, deepsec, codecrucible, security-audit-skill ve open-code-review. Amaç bu araçları tek bir repoda birleştirmek. Projeye bir SCA modülü ve ek açık kaynak tarayıcılar da eklenecek. Kullanıcı tek bir istekle Claude Code'da saatler süren bir denetim başlatmalı. Denetim, kullanım limiti sıfırlanınca kaldığı yerden devam etmeli.

## Kararlar

| Konu | Karar |
|---|---|
| Ad | `kalkan`. CLI: `kalkan`. Claude Code komutu: `/kalkan` |
| Mimari | Bütün LLM işini Claude Code ve alt ajanları yapar. Motor hiç LLM çağırmaz. |
| Dil | Python 3.11+ çekirdek. codecrucible ve open-code-review'daki Go mantığı Python'a taşınır. Dış araçlar kendi binary'leriyle çalışır. |
| Upstream | İçerik port edilir. Kaynak dosyaların seçici kopyası `third_party/` altında sabit commit'te, LICENSE ve NOTICE ile durur. |
| Platform | Native Windows, Linux ve macOS. İsteyen için bütün araçları içeren bir Docker imajı. |
| SCA | SBOM üretimi, iki veritabanıyla zafiyet eşleme, erişilebilirlik analizi. Lisans uyumu yok. |
| Ek tarayıcılar | IaC ve konteyner: Trivy, Checkov, Hadolint. Sırlar: Gitleaks. Kod kalıpları: Opengrep (kendi kurallarımızla), Bandit, gosec. zizmor, TruffleHog, Semgrep kuralları ve CodeQL yok. |
| Kurulum | Bootstrap betikleri sabit sürümleri indirir, checksum ve imza doğrular. `kalkan doctor` eksikleri gösterir. |
| PoC | v1'de var. Ağı kapalı Docker sandbox. Birim düzeyi ve uygulama düzeyi (compose). Docker yoksa bulgu `needs_validation` kalır. |
| Devam | Elle (`/kalkan devam`) ve otomatik (`scripts/run-unattended`). |
| Host | v1 yalnızca Claude Code. Çekirdek host'tan bağımsız. Codex Faz 9'da gelir. |
| Rapor dili | Türkçe. Yaygın teknik terimler İngilizce kalır. Rapordan sonra ajan İngilizce sürüm isteyip istemediğini sorar. |
| Arayüz dili | Ajan talimatları ve CLI mesajları İngilizce. Raporlar ve `README.tr.md` Türkçe. |
| Lisans | MIT. Port edilen Apache-2.0 dosyalar kendi lisans başlığını ve NOTICE atfını korur. |
| Uzak repo | GitHub: `dtechcloud/kalkan`. |

## Sonuçlar

- Motor LLM çağırmadığı için bütün kota tek bir host'ta kalır. Devam etme mantığı tek bir yerde durur.
- Go mantığı Python'a taşındığı için kendi kodumuzda tek bir çalışma zamanı var. Dış araçlar ayrı binary olarak kurulur.
- PoC için Docker opsiyonel. Docker yoksa bulgular `needs_validation` kalır.
- Codex desteği Faz 9'a kaldı. Çekirdek bu yüzden host'tan bağımsız tasarlanır.
- Lisans MIT. Apache-2.0 bileşenlerin atıfları `NOTICE` ve `THIRD_PARTY.md` dosyalarında durur.

## Reddedilen seçenekler

- **Upstream motorları LLM motoru olarak çalıştırmak:** kota çakışması, Windows sorunları ve dağınık devam mantığı.
- **Git submodule:** Windows'ta klonlama ve kurulum karmaşıklaşır.
- **Sıfırdan yazmak:** iş yükü fazla ve kanıtlanmış içerik kaybolur.
- **Yalnızca WSL2 veya yalnızca Docker:** native Windows kullanımı zorlaşır.
- **Apache-2.0 veya 0BSD lisansı:** proje sahibi en serbest yaygın lisansı istedi. MIT bu tercihe en iyi uyan yaygın OSI lisansı.
