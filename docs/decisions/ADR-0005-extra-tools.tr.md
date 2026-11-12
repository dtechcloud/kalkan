# ADR-0005: Ek tarayıcılar ve kurallar
[English](ADR-0005-extra-tools.md) | Türkçe

- Durum: kabul edildi (öneri 2026-10-19, kabul 2026-10-25)
- Değiştirdiği karar: ADR-0001, "Ek tarayıcılar" satırı

## Bağlam

ADR-0001 ek tarayıcıları Trivy, Checkov, Hadolint, Gitleaks, Opengrep, Bandit ve gosec ile sınırladı. Aynı satır zizmor, TruffleHog, Semgrep kuralları ve CodeQL'i dışarıda bıraktı. Semgrep kuralları ve CodeQL için gerekçe lisanstı. zizmor için bir gerekçe yazılmadı. TruffleHog için önce bir AGPL politikası istendi.

2026-10-19'daki araç taraması ve ilk test denetimleri şu açıkları gösterdi:

- GitHub Actions ve diğer CI dosyalarında zayıf kapsam. Checkov GitHub Actions için yalnızca 8 kontrol yapıyor.
- Checkov Helm chart'larını taramıyor, çünkü kalkan `helm` binary'sini kurmuyor.
- Kopyalanmış JS kütüphaneleri SCA'ya görünmüyor.
- Yerel OSV veritabanındaki bilinen zararlı paketler (`MAL-`) sıradan CVE gibi işleniyor.
- Sürüm sorgusu taramalarla aynı ağ kısıtını kullanmıyor.
- Sır taramasında tek motor var. Kabuk betikleri, C/C++ ve depo güvenlik duruşu için araç yok. SBOM teslim edilmiyor.

Proje sahibi 2026-10-25'te güvenlik ekosisteminin olabildiğince geniş kapsanmasını istedi: bir kişi 1-2 komutla yazılımını uçtan uca denetleyebilmeli. Onay beklemeden araç araştırma ve entegrasyon yetkisi verdi. Bu ADR o tarihte kabul edildi.

## Karar

### Her yeni araç için kurallar

1. Pin günü, release tarihinden en az 14 gün sonra olur.
2. SHA-256 upstream checksum dosyasından gelir. Dosya yoksa GitHub asset digest'inden gelir ve indirilen dosyayla karşılaştırılır.
3. Hedefin yapılandırma ve ignore dosyaları yüklenmez. Hedefteki bastırma yorumları varsayılan olarak yok sayılır (ADR-0003). Kapatılamayan bir kaynak durum dosyasına yazılır.
4. Her ağ özelliği kapanır: doğrulama, güncelleme kontrolü, telemetri. `docs/SECURITY.md` söz 3 tablosu bir satır alır. Proxy tuzağı testi aracı kapsar ve sıfır bağlantı ister.
5. Araç hedef kodu değiştirmez, çalıştırmaz, derlemez.
6. Windows, Linux ve macOS desteklenir. Bir platform için ikili dosya yoksa araç yönetilen Go ile kaynaktan (`go-install`) ya da pip ile kurulur.
7. Lisans kuralı aşağıdaki "Lisans politikası" bölümünde. GPL ve AGPL araçlar değiştirilmeden ayrı süreç olarak çalışır (Hadolint gibi).
8. Araç girmeden önce bir corpus üzerinde mevcut araçlarla karşılaştırılır (en az kalkan'ın `vulnapp` fixture'ı ve güvenli ikizleri).

### 2026-10-25 ve 2026-10-26'da eklenenler

| Alan | Araç veya veri | Lisans | Kurulum | Plan |
|---|---|---|---|---|
| GitHub Actions güvenliği | zizmor | MIT | PyPI wheel'den yalnızca çalıştırılabilir dosya | K.5 |
| İş akışı denetimi | actionlint | MIT | ikili dosya | yeni |
| Çoklu CI tedarik zinciri (GitHub Actions, GitLab CI, Azure Pipelines, Tekton) | poutine | Apache-2.0 | `go-install` | K.10 |
| Depo güvenlik duruşu | OpenSSF Scorecard (`--local`) | Apache-2.0 | ikili dosya | yeni |
| Sırlar, ikinci motor (git geçmişi dahil) | Kingfisher | Apache-2.0 | ikili dosya | yeni (K.6'nın amacını karşılar) |
| Kabuk betikleri | ShellCheck | GPL-3.0 | ikili dosya, ayrı süreç | yeni |
| C/C++ | flawfinder | GPL-2.0 | pip, ayrı süreç | yeni |
| nginx yapılandırması | gixy-ng | MPL-2.0 | pip | K.11 |
| Kopyalanmış JavaScript kütüphaneleri | retire.js `jsrepository-v5.json` (veri) | Apache-2.0 | `kalkan sca update-db` | K.7 |
| SBOM teslimatı | Syft çıktısı + pinler + kopyalanmış kütüphaneler (CycloneDX 1.6, SPDX 2.3) | — | mevcut | yeni |
| Tek komut | `kalkan audit`, `kalkan-audit`, `scripts/install.*` | — | — | yeni |
| Helm chart'ları | helm (yalnızca `helm template`, bağımlılık güncellemesi yok) + Checkov (`helm-checkov`) | Apache-2.0 | ikili dosya | K.3 |
| OpenAPI güvenliği | vacuum (OWASP kural seti, `--remote=false`) | MIT | ikili dosya | K.9 |
| Ek Opengrep kural paketleri (`opengrep-packs`) | GitLab sast-rules (MIT ve LGPL-3.0), 0xdea (MIT), Trail of Bits (AGPL-3.0), opengrep-rules (LGPL-2.1 + Commons Clause); 966 kural | lisansı her pakette | `third_party/` + `rules/opengrep-packs/` | K.8 |
| Zararlı paketler | OSV `MAL-` ve Grype zararlı kod kayıtları → `malicious-dependency` sınıfı, kritik | — | mevcut veritabanları | K.2 |
| Yeni matcher kuralları | PSA etiketsiz Namespace, digest'siz `FROM`, lockfile kayıt adresi ve `integrity`, http paket indeksi, commit edilmiş ikili dosyalar | — | `rules/matchers/` | K.4, K.12 |
| Güvenli sürüm sorguları | `probe_env`: minimal ortam, boş çalışma klasörü, güncelleme kontrolü kapalı | — | — | K.1 |

### Planlananlar

- K.6 Betterleaks: Kingfisher eklendi. Betterleaks yalnızca bir ölçüm Gitleaks ve Kingfisher'a göre anlamlı bir fark gösterirse girer.
  - Ölçüm 2026-10-29: anlamlı fark yok, Betterleaks eklenmedi.
- Slither (Solidity) ve DevSkim kuralları: sonraki dalga.

### Dışarıda kalanlar

| Araç | Neden |
|---|---|
| CodeQL | Tescilli lisans. Kapalı kodda ücretli lisans gerekiyor. |
| Semgrep kural deposu | Semgrep Rules License v1.0 dağıtımı yasaklıyor (ADR-0001 geçerli). |
| TruffleHog | AGPL artık engel değil, ama Kingfisher ve Gitleaks aynı alanı kapsıyor. Üçüncü bir sır motoru gürültüyü artırır. |
| KICS | 2.x sürümleri ikili dosya yayımlamıyor (yalnızca Docker). Checkov aynı IaC çerçevelerinin çoğunu kapsıyor. İstek olursa yalnızca Docker Compose için kaynaktan kurulabilir. |
| Kubescape | Ölçüm küçük bir fark ve bir ağ sızıntısı gösterdi (bu karardan önce ölçüldü). |
| Slither | Sözleşme başına solc derleyicisi gerekiyor (AGPL artık engel değil). Sonraki dalga. |
| DevSkim | .NET çalışma zamanı gerekiyor. Kuralları ileride matcher'a taşınabilir. |
| DAST araçları (ZAP, Nuclei) | Çalışan uygulama gerekiyor. kalkan hedefi çalıştırmaz (ADR-0004). |
| Konteyner imajı taraması | İmaj çekmek ağ kullanır ve kullanılan imajları kayıt servisine bildirir. |
| Lisans uyumu | ADR-0001 kararı geçerli. Kaynak repoda bağımlılık lisansları çevrim dışı çoğunlukla bilinmiyor. |

## Lisans politikası (karar 2026-10-25)

Proje sahibi 2026-10-25'te kalkan'dan para kazanmayacağını söyledi ve lisanslara uyan her bileşene izin verdi. Bu kararla 19 Ekim'deki açık soru (K.13) kapandı.

1. OSI onaylı lisanslar (MIT, Apache-2.0, BSD, MPL, LGPL, GPL) serbest.
2. AGPL-3.0 serbest. Araçlar değiştirilmeden ayrı süreç olarak çalışır. Kural dosyaları değiştirilmeden `third_party/` altında, lisans metni ve kaynak commit'iyle durur. kalkan bir ağ hizmeti olarak sunulmaz. Bu yüzden AGPL'in ağ maddesi bir yükümlülük doğurmaz.
3. Yalnızca satışı yasaklayan lisanslar (Commons Clause) ticari olmayan kullanımda serbest. Bu bileşenler ayrı bir klasörde durur ve bir anahtarla kapatılabilir.
4. Kuralları başkalarına açmayı veya hizmet olarak sunmayı yasaklayan lisanslar (Semgrep Rules License v1.0) ve tescilli lisanslar (CodeQL) dışarıda kalır.
5. kalkan ileride paylaşılırsa veya ticari kullanılırsa, 2. ve 3. maddedeki bileşenler yeniden değerlendirilir. `THIRD_PARTY.md` her bileşenin lisansını gösterir. Güncelleme (2026-11-06): kalkan artık public. Madde 3 artık geçerli değil, çünkü tek Commons Clause paketi kaldırıldı (sondaki nota bak).

Bu politikayla eklenenler: Trail of Bits semgrep-rules (AGPL-3.0) ve opengrep-rules (LGPL-2.1 + Commons Clause), K.8 kural paketleriyle aynı kalite süzgecinden geçer.

## Sonuçlar

- Doctor'daki araç sayısı artar. İlk kurulum uzar ve disk kullanımı artar.
- Deterministik faz uzar. Her araç kendi zaman sınırıyla çalışır ve hedefte ilgili dosya yoksa atlanır.
- Araç sonuçları "doğrulanmamış araç sonucu" olarak rapora girer. Ajanlar bu sonuçları ipucu olarak kullanır. Doğrulama bütçesi en yüksek ciddiyetli sonuçlara gider.
- `kalkan tools install --all`, bootstrap, plugin kurulumu, `kalkan doctor` ve Docker imajı araçları manifestten okur.
- ADR-0001 değişmez. Ek tarayıcılar için ADR-0005 onun yerine geçer.

## Uygulama notları (2026-10-25)

Karar aynı kaldı. Entegrasyon sırasında şu ayrıntılar netleşti:

- **gixy:** pip ile kuruldu (`gixy-ng==0.2.55`, MPL-2.0). Sürüm ikili dosyaları Business Source License 1.1 lisanslı redoctor'u içeriyor. Bu lisans OSI onaylı değil.
- **zizmor:** PyPI wheel dosyalarından yalnızca çalıştırılabilir dosya çıkarılıyor. Windows on Arm, x64 yapıyı emülasyonla çalıştırıyor.
- **poutine:** her platformda `go-install` ile kuruluyor. Sürüm kontrolü (`--disable-version-check`) kapalı. Upstream hatası: Windows'ta GitHub iş akışlarını okumuyor (yol eşleştirmesi `/` ile). Rapor bu açığı `platform_gap` olarak yazıyor.
- **OpenSSF Scorecard:** yerel modda yalnızca ağ kullanmayan altı kontrol çalışıyor (Binary-Artifacts, Dangerous-Workflow, Dependency-Update-Tool, License, Security-Policy, Token-Permissions). Pinned-Dependencies Docker Hub'a bağlandığı için dışarıda. Windows'ta iş akışı kontrolleri aynı yol hatası yüzünden sonuç vermiyor.
- **Kingfisher:** doğrulama ve güncelleme kontrolü kapalı, değerler gizleniyor. Adaptör, gizlenmemiş bir değer görürse çalışmayı durduruyor.
- **ShellCheck:** satır içi `# shellcheck disable=` yönergeleri 0.11.0'da kapatılamıyor. Durum dosyası bunu kaydediyor.
- **Checkov:** `helm` ve `kustomize` çerçeveleri ağ bağlantısı açtığı için kapatıldı. Checkov boş bir ev klasörüyle çalışıyor, böylece bir platform anahtarı dosyası okunamıyor.
- **Docker:** araç listeleri manifestten üretiliyor (`docker/manifest_tools.py`). GPL araçları (Hadolint, ShellCheck, flawfinder) `WITH_GPL` katmanında.
- **Kural 1 (14 gün):** 2026-10-25'te dört araç bu kuralı bozuyordu: zizmor 1.31.1 (release 2026-10-15), Kingfisher 2.14.0 (2026-10-20), OpenSSF Scorecard 5.6.0 (2026-10-12) ve gixy-ng 0.2.58 (2026-10-25). Her biri 2026-10-11 veya öncesinde yayımlanan en yeni kararlı sürüme geçti: zizmor 1.30.1, Kingfisher 2.11.1, Scorecard 5.5.0, gixy-ng 0.2.55. Her manifest girdisi artık `released_at` ve `pinned_at` alanlarını taşıyor. Bir birim testi, pin günü release gününden 14 gün sonra değilse başarısız oluyor. Go 1.26.9 (release 2026-10-08) 2026-10-16'da pinlenmişti. 2026-10-25'te altı arşiv yeniden indirildi ve bütün değerler eşleşti. `pinned_at` bu günü gösteriyor.
- **gixy 0.2.55:** Python API'sinde `load_default_vars` seçeneği yok. Bu sürüm makinenin değişken klasörlerini zaten okumuyor. Başlatıcı seçeneği yalnızca `Config` onu tanıyorsa veriyor.
- **Sürüm sorguları (K.1):** `kalkan doctor` ve `resolve` her aracın sürüm komutunu tarayıcılarla aynı en küçük ortamla ve boş bir çalışma klasöründe çalıştırıyor. Manifest, güncelleme kontrolünü kapatan bayrakları (`version_args`) ve değişkenleri (`version_env`) taşıyor. Değişiklikten önce `checkov --version` pypi.org'a, `govulncheck -version` vuln.go.dev'e bağlandı. Sonra proxy tuzağı sıfır bağlantı gördü.
- **Trivy:** 0.75.0, Helm chart'larını işlerken `values.schema.json` içindeki uzak `$ref` dosyalarını indiriyor ve bunu kapatan bir seçeneği yok. Yerel modda Trivy'nin `helm` misconfig tarayıcısı kapalı. Chart'ları `helm-checkov` tarıyor.
- **vacuum:** 0.33.0, `--remote=false` ile de hedefin dışındaki yerel `$ref` dosyalarını okuyor (Windows'ta UNC yolu bir SMB bağlantısı açabilir). kalkan her referansı önce kendisi kontrol ediyor ve hedefin dışına çıkan bir belgeyi taramıyor.
- **helm:** 4.3.0, `--skip-schema-validation` ile çalışıyor. Bu bayrak olmadan uzak şema indiriliyor. Bağımlılığı eksik chart bir tarama boşluğu oluyor.
- **GitLab sast-rules:** dosyalar LGPL-2.1 değil, LGPL-3.0-only lisanslı (MIT dosyalarıyla birlikte). `rules/lgpl-cc` (Commons Clause), `rules/gitlab` (tescilli), flawfinder ve gosec portları alınmadı.
- **Kural paketleri:** `third_party/` altındaki kopyalar değişmedi. Çalışma için üretilen `rules/opengrep-packs/` dosyaları bu kuralların yeniden girintilenmiş birleşimleri. Her dosyanın başlığı ve `NOTICE` bu değişikliği yazıyor. `KALKAN_RULE_PACKS=osi` AGPL ve Commons Clause paketlerini kapatıyor.
- **14 gün kuralı:** zizmor 1.30.1, Kingfisher 2.11.1, Scorecard 5.5.0 ve gixy-ng 0.2.55'e indirildi. Her araç kaydı `released_at` ve `pinned_at` taşıyor. Bir birim testi kuralı her kayıtta denetliyor.

## Güncelleme (2026-11-06)

opengrep-rules paketi kaldırıldı, çünkü Commons Clause şartı ücretli danışmanlık ve destek hizmetlerini yasaklıyor. kalkan yerine serbest lisanslı kurallar arıyor.
