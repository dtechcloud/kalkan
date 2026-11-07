# ADR-0007: Serbest lisanslı kural paketleri opengrep-rules paketinin yerini alır
[English](ADR-0007-permissive-rule-packs.md) | Türkçe

- Durum: kabul edildi
- Tarih: 2026-11-07
- Karar veren: proje sahibi
- İlgili: ADR-0005 (kural paketleri, K.8 ve lisans politikası; bu karar onu genişletir)

## Bağlam

Sürüm 1.15.0, opengrep-rules paketini çıkardı (tutulan 461 kural). Paketin lisansı Commons Clause eklenmiş LGPL-2.1. Commons Clause, değerini bu kurallardan alan ücretli danışmanlık ve destek hizmetlerini yasaklıyor. vulnapp fixture'ında 17 yerleştirilmiş açık, tek paket sonucunu kaybetti. kalkan'ın kendi kuralları 17'sini de bulmaya devam etti.

Proje sahibi serbest lisanslı yedek kurallar istedi: bir MIT reposunda yeniden dağıtıma ve ücretli danışmanlık dahil ticari kullanıma izin verilmeli. 2026-11-07'deki tarama, her adayın LICENSE dosyasını kendi reposunda okudu. Hiçbir serbest paket, çıkarılan paket kadar dili tek başına kapsamıyor.

## Karar

1. kalkan yedi paketi daha `third_party/` altına alır. Her biri lisans dosyalarıyla ayrı bir bileşendir:

   | Paket | Upstream | Lisans | Tutulan kural |
   |---|---|---|---|
   | `atlassian` | atlassian-labs/atlassian-sast-ruleset | LGPL-2.1-only | 31 |
   | `elttam` | elttam/semgrep-rules | MIT | 28 |
   | `njsscan` | ajinabraham/njsscan | LGPL-3.0-or-later | 41 |
   | `mobsfscan` | MobSF/mobsfscan | LGPL-3.0-or-later | 73 |
   | `mindedsecurity` | mindedsecurity/semgrep-rules-android-security | GPL-3.0-only | 25 |
   | `aikido` | AikidoSec/opengrep-rules | MIT | 2 |
   | `semgrep-codeql` | andrew/semgrep-codeql | MIT (github/codeql'den çevrildi, MIT) | 28 |

2. Yedi paketin hepsi `osi` lisans grubundadır. LGPL ve GPL OSI onaylıdır ve ticari kullanıma izin verir. `KALKAN_RULE_PACKS=osi` yine yalnız AGPL paketini kapatır.
3. Copyleft paketler kendi klasörlerinde, lisans metinleriyle kalır. `rules/opengrep-packs/<paket>/` altındaki değiştirilmiş bundle'lar paketin lisansını korur ve kaynakları bu repodadır.
4. Başlığında başka bir kaynak adı geçen kural dosyaları alınmaz: Semgrep'in semgrep-rules reposu (2020-10-29'dan önce lisanssız, sonra Commons Clause) ve mobsfscan içindeki GPL-3.0 mindedsecurity kuralları. Bunlar njsscan ve mobsfscan'den 14 dosya.
5. Her pin, 2026-11-07 pin gününde en az 14 günlük (ADR-0005, kural 1). njsscan ve mobsfscan için kalkan 2026-10-24'ten önceki son commit'i sabitler.
6. Seçim yalnız sınıfı belli güvenlik kurallarını tutar. Şunları çıkarır: sertleştirme önerileri ve iyi kontrol işaretleri (tür `best-practice`), veri akışı olmayan inceleme işaretleri (`audit`), Trivy, Checkov, zizmor ve actionlint'in zaten kontrol ettiği Kubernetes ve GitHub Actions kuralları (`covered`), kod kalitesi kuralları (`non-security`), gürültülü kurallar (`noisy`), Opengrep 1.30.1'in reddettiği join modu kuralı (`parse`) ve vulnapp'in güvenli ikizini raporlayan kurallar (`twin-fp`). Otomatik tekrar kontrolü, bir GitLab port'unu tekrarlayan 57 kuralı çıkarır. `duplicate` türü, port'tan sonra deseni değişen 6 kuralı daha adıyla çıkarır.
7. semgrep-codeql kuralları bir LLM çevirisinden geldi ve upstream'de testleri yok. Yeni seçim anahtarı `keep_only`, yalnız güvenli bir ikize veya başka bir koda değmeden yerleştirilmiş bir vulnapp açığını bulan 28 kuralı tutar. Kalan 259 kural `unmeasured` türüyle çıkar. Bu paketin GitHub Actions, sır ve C kuralları da alınmaz, çünkü zizmor, Gitleaks, Kingfisher, flawfinder ve 0xdea paketi onları kapsıyor.
8. Kök `NOTICE` dosyası her yeni bileşenin adını verir ve CodeQL sorgularının GitHub telif notunu tekrarlar.

## Sonuçlar

- Paketler 55 bundle'da 733 kural tutar (önce 505). kalkan'ın kendi 106 kuralıyla Opengrep 839 kural çalıştırır.
- vulnapp'te 34 yerleştirilmiş açığın paket sonucu var (önce 18). 1.15.0'ın kaybettiği 17 açığın 8'i yine paket sonucu alır, hepsi semgrep-codeql üzerinden. Hiçbir sonuç güvenli bir ikize değmez ve yerleştirilmiş açıkların dışındaki sonuçlar aynı 3 sonuç olarak kalır. Adaptör 17,6 saniye sürer (önceki üç paket tek başına: 14,7 saniye).
- semgrep-codeql alt kümesi vulnapp üzerinde seçildi. Bu yüzden vulnapp'teki sonucu bağımsız bir ölçüm değil. Değerini başka hedeflerde bir benchmark doğrulamalı.
- Açık kalan boşluklar: Python SSRF, JavaScript SSTI ve XXE, Go XSS, Java XXE, PHP SQL injection ve komut enjeksiyonu, Ruby komut enjeksiyonu ve open redirect, ayrıca Solidity (serbest bir Solidity paketi bulunamadı).
- `curation.json` ve `scripts/build_opengrep_packs.py`, `keep_only` anahtarını ve `unmeasured` çıkarma türünü kazanır.
