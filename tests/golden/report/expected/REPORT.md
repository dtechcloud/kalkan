# Güvenlik denetim raporu: shop

| Alan | Değer |
|---|---|
| Çalıştırma ID | `20261015T120000Z-shop-a1b2` |
| Hedef | `C:/projects/shop` |
| Hedef türü | Yerel klasör |
| Git commit | — |
| Profil | standard |
| Çalıştırma dili | tr |
| Başlangıç | 2026-10-15 09:30 UTC |
| Son güncelleme | 2026-10-15 12:00 UTC |
| Rapor tarihi | 2026-10-15 12:30 UTC |
| Aşama | Rapor |
| Durum | Tamamlandı |
| Teknolojiler | `docker`, `flask`, `python` |

## 1. Yönetici özeti

kalkan 2 bulguyu doğruladı. En yüksek ciddiyet: Yüksek. 1 bulgu doğrulama bekliyor. Doğrulayıcı 1 aday bulguyu reddetti. Araçlar 2 doğrulanmamış sonuç verdi. Dikkat: 1 bağımlılık bilinen zararlı paket sürümü. Bu paketler kurulurken kod çalıştırır. 8.1 bölümündeki adımları hemen uygula. SCA 5 bağımlılık zafiyeti buldu. 1 kayıt erişilebilir (reachable).

> **Kısmi geçiş (partial pass).** Bu rapor hedefin tamamını kapsamıyor olabilir. Sebepler 2. bölümde.

| Ölçüt | Sayı |
|---|---|
| Doğrulanan bulgu | 2 |
| Ciddiyet: Kritik | 0 |
| Ciddiyet: Yüksek | 1 |
| Ciddiyet: Orta | 1 |
| Ciddiyet: Düşük | 0 |
| Ciddiyet: Bilgi | 0 |
| Doğrulama bekleyen | 1 |
| Reddedilen | 1 |
| Doğrulanmamış araç sonucu | 2 |
| SCA kaydı | 5 |
| Zararlı bağımlılık | 1 |

*Ciddiyet sayıları yalnızca doğrulanan bulguları kapsar.*

### 1.1 Bulgu listesi

| ID | Başlık | Ciddiyet | Karar | Konum |
|---|---|---|---|---|
| `KF-CF0FB1E8E50E80FC` | Kullanıcı aramasında SQL injection | Yüksek | Doğrulandı | `app/db.py:8` |
| `KF-760073988BED4CB8` | Görsel proxy'sinde SSRF | Orta | Doğrulandı | `app/routes.py:19` |
| `KF-32409FEA7A491CFA` | Dosya okumada path traversal | — | Doğrulama gerekiyor | `app/routes.py:25` |
| `KF-C4BCAA828C227419` | Router \`admin\` \| &lt;script&gt;alert('x')&lt;/script&gt; yetki atlatma | — | Reddedildi | `app/routes.py:31` |

## 2. Kapsam

> **Kısmi geçiş (partial pass).** Bu rapor hedefin tamamını kapsamıyor olabilir. Sebepler:
>
> - 1 kapsam birimi kapanmadı (planned, in_progress, deferred veya blocked).
> - 1 bağımlılık manifest dosyasının lockfile dosyası yok. SCA bu dosyaların sürüm aralıklarını ve dolaylı bağımlılıklarını kontrol etmedi.

### 2.1 Profil ve bütçe

Profil: standard. Ajan görevi bütçesi: 13 / 150 kullanıldı.

### 2.2 Aşamalar

| Aşama | Durum | Başlangıç | Bitiş |
|---|---|---|---|
| Hazırlık | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Deterministik tarama | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| SCA | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Keşif (recon) | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Plan | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Avlanma (hunt) | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Doğrulama | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| PoC | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Birleştirme (merge) | Bitti | 2026-10-15 12:00 UTC | 2026-10-15 12:00 UTC |
| Rapor | Sürüyor | 2026-10-15 12:00 UTC | — |

### 2.3 Tarayıcılar

| Motor | Grup | Durum | Sürüm | Süre | Not |
|---|---|---|---|---|---|
| `bandit` | Tarama | Çalıştı | `1.9.4` | 3.0 sn | — |
| `gitleaks` | Tarama | Çalıştı | `8.30.1` | 1.2 sn | — |
| `opengrep` | Tarama | Çalıştı | `1.30.1` | 12.4 sn | — |
| `trivy` | Tarama | Atlandı | — | 0.0 sn | tool not installed: trivy |
| `grype` | SCA | Atlandı | — | 0.0 sn | offline: no vulnerability database |
| `osv-scanner` | SCA | Çalıştı | `2.6.0` | 4.5 sn | — |
| `retirejs` | SCA | Çalıştı | `jsrepository-v5 2026-10-15 sha256:c213444cbf88` | 0.4 sn | JavaScript files checked: 1; vendored library versions: 1 (files: 1) |
| `syft` | SCA | Çalıştı | `1.54.0` | 3.2 sn | — |

### 2.4 Kapsam defteri (coverage ledger)

| Birim durumu | Sayı |
|---|---|
| Aday bulgu var (candidate) | 2 |
| İncelendi (covered) | 1 |
| Ertelendi (deferred) | 1 |
| Uygulanamaz (not\_applicable) | 1 |
| **Toplam** | **5** |

**Son inceleme.** 2 kayıt ikinci, bağımsız bir incelemeden geçti: 1 doğrulandı, 1 düşürüldü, 0 reddedildi. İncelenmeyen doğrulanmış veya doğrulama bekleyen kayıt: 1.

### 2.5 Eksik girdiler

Bütün girdiler okundu.

### 2.6 Tarama boşlukları

Araçlar bu dosyaları tam olarak tarayamadı. Bu dosyalarda sonuç olmaması, dosyanın temiz olduğunu göstermez.

Bu manifest dosyalarının yanında lockfile yok. SCA araçları paket sürümlerini ve dolaylı bağımlılıkları lockfile dosyasından okur. kalkan bu dosyaların tam sürümlerini (exact pin) ayrıca kontrol etti.

| Dosya | Ekosistem | Kontrol edilen tam sürüm | Kontrol edilmeyen aralık | Gerekçe |
|---|---|---|---|---|
| `web/package.json` | npm | 1 | 2 | Sürüm aralıkları var, lockfile yok |

`opengrep` 1 dosyayı yalnızca kısmen analiz etti (parse hatası veya araç içi hata).

- `app/helpers.py`

`opengrep` 1 dosyayı atladı.

Sebepler:

- files larger than 1.0 MB: 1

Dosyalar:

- `static/bundle.min.js`

1 dosyanın tam yolu 260 veya daha fazla karakter. Opengrep bu dosyaları uyarı vermeden atlayabilir. Sebep: Opengrep'in çekirdek programı uzun yolları desteklemiyor. LongPathsEnabled=1 bu sınırı kaldırmıyor. Bu makinede LongPathsEnabled: açık. Çözüm: `KALKAN_RUNS_DIR` değişkenini kısa bir klasöre (örneğin `C:/kr`) ayarla. Sonra yeni bir çalıştırma başlat.

## 3. Doğrulanan bulgular

Motor bir bulguyu iki yolla doğrular: üç soru, motorun kaynakta bulduğu alıntılarla kanıtlanır veya sandbox içindeki PoC zafiyeti gösterir. Bulgular ciddiyete göre sıralı.

### 3.1 Yüksek · Kullanıcı aramasında SQL injection

| Alan | Değer |
|---|---|
| ID | `KF-CF0FB1E8E50E80FC` |
| Ciddiyet | Yüksek (olasılık: Yüksek, etki: Yüksek) |
| Güven | Orta |
| Sınıf | SQL injection (`sqli`) |
| CWE | CWE-89 |
| OWASP | A03:2021 |
| Konum | `app/db.py:8` |
| Motorlar | `hunter`, `verifier`, `opengrep`, `reviewer` |
| Son inceleme | Doğrulandı: Kayıttaki her yol ve satır kaynakla uyuşuyor; f-string, id değerini SQL metnine koyuyor. |
| Bağlı adaylar | `CAND-7FB0BF0A3BDA3C13` |
| PoC | PoC kaydı yok |
| Çalışma zamanı doğrulaması | Yapılmadı |

**Açıklama.** GET /users, id parametresini SQL sorgusuna doğrudan ekliyor.

**Kök neden.** find\_user, SQL metnini f-string ile kuruyor.

**Beklenen davranış.** Sorgu, user\_id değerini parametre olarak bağlamalı.

**Akış (trace)**

| # | Tür | Konum | Kapsam | Açıklama |
|---|---|---|---|---|
| 1 | Giriş (entrypoint) | `app/routes.py:12` | `get_user` | id değerini query string'den okuyor. |
| 2 | Sink | `app/db.py:8` | `find_user` | Biçimlenmiş SQL metnini çalıştırıyor. |

**Kanıt**

- `app/db.py:8`: f-string, user\_id değerini SQL metnine koyuyor.

**Üç soru**

| Soru | Yanıt | Gerekçe | Alıntılar |
|---|---|---|---|
| Saldırgan girdiyi kontrol ediyor mu? | Kanıtlandı | id değeri HTTP isteğinin query string'inden geliyor. | `app/routes.py:12` `user_id = request.args.get("id")` |
| Bir yetki sınırı aşılıyor mu? | Kanıtlandı | Oturum açmış her kullanıcı başka kullanıcıların satırlarını okuyabilir. | `app/routes.py:10` `@login_required` |
| Etkili bir önlem eksik mi? | Kanıtlandı | Değer bağlama veya doğrulama olmadan SQL metnine giriyor. | `app/db.py:8` `cur.execute(f"SELECT * FROM users WHERE id = {user_id}")` |

**Koşullar**

- Kimlik doğrulama seviyesi: Saldırganın normal bir kullanıcı hesabı olmalı.

**Saldırı senaryosu**

**Saldırgan.** Normal hesabı olan, oturum açmış bir kullanıcı.

Adımlar:

1. Normal kullanıcı olarak oturum aç.
2. GET /users?id=1%20OR%201=1 isteğini gönder.

Payload:

```text
1 OR 1=1
```

**Gözlenen sonuç.** Yalnızca statik analiz: payload cur.execute çağrısına değişmeden ulaşıyor.

**Düzeltme.** Bağlanmış parametre kullan.

Kod değişikliği: `app/db.py`

```text
cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
```

### 3.2 Orta · Görsel proxy'sinde SSRF

| Alan | Değer |
|---|---|
| ID | `KF-760073988BED4CB8` |
| Ciddiyet | Orta (olasılık: Yüksek, etki: Orta) |
| Güven | Yüksek |
| Sınıf | Server-side request forgery (SSRF) (`ssrf`) |
| CWE | CWE-918 |
| OWASP | A10:2021 |
| Konum | `app/routes.py:19` |
| Motorlar | `hunter`, `verifier`, `poc-builder` |
| Son inceleme | İncelenmedi |
| PoC | Başarılı · birim (unit) |
| Çalışma zamanı doğrulaması | Tekrarlandı: PoC etkiyi sandbox'ta gösterdi |

**Açıklama.** GET /fetch, kullanıcının verdiği adrese sunucudan istek atıyor.

**Kök neden.** fetch, url değerini doğrulamadan http\_get'e veriyor.

**Beklenen davranış.** Sunucu yalnızca izin listesindeki adreslere istek atmalı.

**Akış (trace)**

| # | Tür | Konum | Kapsam | Açıklama |
|---|---|---|---|---|
| 1 | Giriş (entrypoint) | `app/routes.py:18` | `fetch` | url değerini query string'den okuyor. |
| 2 | Sink | `app/routes.py:19` | `fetch` | Sunucu, kullanıcının verdiği adrese istek atıyor. |

**Kanıt**

- `app/routes.py:19`: http\_get, doğrulanmamış url değerini kullanıyor.

**Üç soru**

| Soru | Yanıt | Gerekçe | Alıntılar |
|---|---|---|---|
| Saldırgan girdiyi kontrol ediyor mu? | Kanıtlandı | url değeri query string'den geliyor. | `app/routes.py:18` `url = request.args.get("url")` |
| Bir yetki sınırı aşılıyor mu? | Bilinmiyor | unverified\_evidence | — |
| Etkili bir önlem eksik mi? | Kanıtlandı | Adres doğrulaması yok. | `app/routes.py:19` `return http_get(url)` |

**Saldırı senaryosu**

**Saldırgan.** Kimliği doğrulanmamış uzak bir saldırgan.

Adımlar:

1. GET /fetch?url=http://169.254.169.254/latest/meta-data/ gönder.

Payload:

```text
http://169.254.169.254/latest/meta-data/
```

**Gözlenen sonuç.** Harness, 169.254.169.254 adresine giden isteği yakaladı.

**PoC sonucu (Başarılı · birim (unit)).** Harness, 169.254.169.254 adresine giden isteği yakaladı.

PoC dosyaları: `poc/KF-760073988BED4CB8/out/stdout.txt`

**Düzeltme.** Hedef adresi bir allowlist ile sınırla.

## 4. Doğrulama gerektiren bulgular

Bu bulgular için kanıt eksik. Ciddiyet verilmez. Engelleri ve doğrulama planını oku.

### 4.1 Dosya okumada path traversal

| Alan | Değer |
|---|---|
| ID | `KF-32409FEA7A491CFA` |
| Sınıf | Path traversal (`path-traversal`) |
| CWE | CWE-22 |
| Konum | `app/routes.py:25` |
| Motorlar | `hunter`, `verifier` |
| Son inceleme | Düşürüldü: Uygulama dosya adını hiç normalize etmiyor; tek açık soru, önündeki reverse proxy'nin ../ dizilerini engelleyip engellemediği. |
| PoC | Çalışmadı · birim (unit) |
| Çalışma zamanı doğrulaması | Yapılmadı |

**Açıklama.** GET /files, name parametresini dosya yoluna ekliyor.

**İddia edilen kök neden.** read\_file, name değerini normalleştirmeden yola ekliyor.

**Engeller**

- Bir reverse proxy ../ dizilerini engelliyor olabilir.
- Uygulama dosya adını hiç normalize etmiyor; tek açık soru, önündeki reverse proxy'nin ../ dizilerini engelleyip engellemediği.
- `sandbox_unavailable`: PoC doğrulama sandbox'ı çalışmadı (Docker kapalı veya erişilemedi).

**Doğrulama planı**

- Yerel: Uygulamayı çalıştır ve name=../../etc/passwd gönder.
- Dağıtım ortamı: Onaylı test ortamında proxy davranışını kontrol et.

**Akış (trace)**

| # | Tür | Konum | Kapsam | Açıklama |
|---|---|---|---|---|
| 1 | Giriş (entrypoint) | `app/routes.py:24` | `read_file` | name değerini query string'den okuyor. |
| 2 | Sink | `app/routes.py:25` | `read_file` | Birleştirilmiş yolu açıyor. |

**Kanıt**

- `app/routes.py:25`: open çağrısı birleştirilmiş yolu kullanıyor.

**PoC sonucu (Çalışmadı · birim (unit)).** Çalışmadı: Docker sandbox yok.

## 5. Reddedilen bulgular

Doğrulayıcı veya son inceleme bu adayları reddetti. Kayıtlar iz için duruyor.

| ID | Başlık | Sınıf | Konum | Gerekçe |
|---|---|---|---|---|
| `KF-C4BCAA828C227419` | Router \`admin\` \| &lt;script&gt;alert('x')&lt;/script&gt; yetki atlatma | `missing-authz` | `app/routes.py:31` | require\_authorization, settings\_update çağrısından önce çalışıyor. |

## 6. Hardening notları

Bu notlar zafiyet değil. Güvenliği artıran iyileştirmeler.

| Başlık | Konum | Not |
|---|---|---|
| Konteyner root olarak çalışıyor | `Dockerfile` | Dockerfile'a bir USER satırı ekle. |
| Hata ayıklama \| &lt;b&gt;modu&lt;/b&gt; | `app/routes.py:6` | \`app.debug\` üretimde kapalı olmalı. |

## 7. Araç sonuçları (doğrulanmadı)

> Bu sonuçları deterministik araçlar üretti. Hiçbir ajan onları doğrulamadı. False positive içerebilir.

### 7.1 bandit (1)

Orta 1

| Ciddiyet | Kural | Başlık | Konum | Sınıf |
|---|---|---|---|---|
| Orta | `B506` | Hostile \| title with \`back\`ticks\`\` and &lt;script&gt;alert(1)&lt;/script&gt; | `app/config.py:7` | `deserialization` |

### 7.2 gitleaks (1)

Yüksek 1

| Ciddiyet | Kural | Başlık | Konum | Sınıf |
|---|---|---|---|---|
| Yüksek | `generic-api-key` | Generic API key | `app/config.py:3` | `hardcoded-secrets` |

## 8. Bağımlılık zafiyetleri (SCA)

> 1 manifest dosyasında lockfile yok. SCA bu dosyaların yalnızca tam sürümlerini kontrol etti. Liste 2.6 bölümünde.

### 8.1 Zararlı bağımlılık

> [!CAUTION]
> **1 paket sürümü bilinen zararlı paket kayıtlarıyla eşleşti (OSV `MAL-`, GitHub malware advisory). Zararlı kod paket kurulurken çalışır. Bu yüzden reachability sonucu önemli değil ve ciddiyet Kritik kalır.**
>
> Yapılacaklar:
>
> 1. Paketi ve bu sürümü kaldır. Lockfile dosyasını yeniden üret.
> 2. Paketi kuran her makineyi açığa çıkmış kabul et: geliştirici makineleri, CI runner'ları ve build imajları.
> 3. Kurulumun okuyabildiği sırları değiştir (rotate): CI secret'ları, token'lar, bulut kimlik bilgileri ve SSH anahtarları.
> 4. Lockfile geçmişinde bu sürümü ekleyen commit'i bul. Ondan sonraki build'leri kontrol et.

| Paket | Sürüm | Ekosistem | Kayıt ID | Ciddiyet | Konum |
|---|---|---|---|---|---|
| `sample-module` | `0.0.1` | PyPI | `MAL-2025-41758`, `GHSA-2g5x-c76j-3h73` | Kritik | `requirements.txt` |

### 8.2 Bilinen zafiyetler

Bu kayıtlar bilinen zafiyetli bağımlılıkları gösterir. Ciddiyet, reachability sonucuna göre düşmüş olabilir.

1 kayıt, lockfile olmayan bir manifest dosyasındaki tam sürümden geliyor. Tablo bu kayıtları `manifest` etiketiyle gösterir.

1 kayıt, projeye kopyalanmış (gömülü) JavaScript dosyalarından geliyor. Hiçbir paket yöneticisi bu dosyaları listelemiyor. Tablo bu kayıtları `gömülü` etiketiyle gösterir. Dosyalar:

- `web/static/js/jquery.min.js` (`jquery 1.12.4`)

| Paket | Sürüm | Ekosistem | Zafiyet ID | Ciddiyet | Düzeltilmiş sürüm | Reachability |
|---|---|---|---|---|---|---|
| `pyyaml` | `5.3` | PyPI | `GHSA-8q59-q68h-6hv4`, `CVE-2020-14343` | Kritik | `5.4` | Erişilebilir |
| `lodash` | `4.17.15` (manifest) | npm | `GHSA-p6mc-m468-83gw`, `CVE-2020-8203` | Yüksek | `4.17.19` | Bilinmiyor |
| `jquery` | `1.12.4` (gömülü) | npm | `GHSA-jpcq-cgw6-v4j6`, `CVE-2020-11023` | Orta | `3.5.0` | Bilinmiyor |
| `requests` | `2.19.0` | PyPI | `GHSA-x84v-xcm2-53pg`, `CVE-2018-18074` | Düşük | `2.20.0` | Erişilemiyor |

SBOM: `report/sbom.cdx.json` (CycloneDX 1.6), `report/sbom.spdx.json` (SPDX 2.3). 5 bileşen (Syft 3, manifest sürümü 1, gömülü JavaScript 1).

## Ek A. Yöntem ve kaynaklar

### A.1 Yöntem

- kalkan her aday bulgu için üç soru sorar: saldırgan girdiyi kontrol ediyor mu, bir yetki sınırı aşılıyor mu, etkili bir önlem eksik mi.
- Doğrulayıcı ajan her yanıtı kaynak koddan bir alıntıyla destekler.
- Motor her alıntıyı kaynakta arar: belirtilen satır ile iki satır öncesi ve sonrası. Kaynakta olmayan alıntı sayılmaz.
- Kararı ajan değil, motor verir. Üç soru kanıtlanırsa bulgu doğrulanır. Bir soru alıntıyla çürütülürse bulgu reddedilir. Diğer durumlarda bulgu doğrulama bekler.
- PoC çalışmadıysa doğrulanan bulgu statik kanıta dayanır. Başarılı bir PoC güven seviyesini yükseltir. Doğrulayıcı gerekli alanları verdiyse, başarılı PoC doğrulama bekleyen bir bulguyu da doğrular.
- Araç sonuçları ve SCA kayıtları deterministik motorlardan gelir. Ajan doğrulaması olmadan bulguya dönüşmez.

### A.2 Araç sürümleri

| Araç | Sürüm | Kurulum |
|---|---|---|
| `bandit` | `1.9.4` | pip |
| `gitleaks` | `8.30.1` | binary |
| `opengrep` | `1.30.1` | binary |
| `osv-scanner` | `2.6.0` | binary |

### A.3 Çalıştırma

| Alan | Değer |
|---|---|
| Çalıştırma ID | `20261015T120000Z-shop-a1b2` |
| kalkan sürümü | `0.0.0-golden` |
| Rapor tarihi | 2026-10-15 12:30 UTC |
| Rapor dosyaları | `REPORT.md`, `REPORT.html`, `EXECUTIVE.html`, `findings.sarif`, `findings.json`, `sbom.cdx.json`, `sbom.spdx.json`, `summary.json` |

### A.4 Uyarılar

- Files with an absolute path of 260 or more characters: 1. Opengrep may skip them without a warning: its core program is not long-path aware, also with LongPathsEnabled=1. Set KALKAN\_RUNS\_DIR to a short folder (for example C:/kr) and start a new run.

---

İngilizce sürüm için önce `kalkan run answer english_report yes` komutunu çalıştır, sonra Claude Code'da `/kalkan devam` yaz.
