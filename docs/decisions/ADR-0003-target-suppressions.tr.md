# ADR-0003: Hedefin bastırma işaretleri yok sayılır
[English](ADR-0003-target-suppressions.md) | Türkçe

- Durum: kabul edildi
- Tarih: 2026-10-16

## Bağlam

Tarayıcılar, taranan kodun kendi bastırma işaretlerine uyar. Örnekler: `# nosec` (Bandit, gosec), `gitleaks:allow` ve `.gitleaksignore` (Gitleaks), `checkov:skip` ve `.checkov.yaml` (Checkov), `nosem` (Opengrep), Hadolint ignore pragmaları.

kalkan bir denetim aracıdır. Denetlenen kod güvenilir değildir. Bir geliştirici veya bir saldırgan bu işaretlerle gerçek bir zafiyeti rapordan gizleyebilir.

## Karar

- Tarayıcı adaptörleri varsayılan olarak hedefin bastırma işaretlerini ve bastırma yapılandırmalarını yok sayar.
- `kalkan scan --honor-suppressions` seçeneği aracın varsayılan davranışını geri getirir.
- Her `scans/<engine>.status.json` dosyası, hangi bastırma kaynağının yok sayıldığını veya uygulandığını kaydeder.
- Hunter ve verifier ajanları bastırma yorumunu bağlam olarak görebilir. Örneğin "geliştirici bu satırı bilerek bastırmış" bilgisini kullanabilirler. Ama karar yine kanıta dayanır.

## Sonuçlar

- Araç sonuçları daha gürültülü olur. Doğrulanmamış araç sonuçları raporda ayrı bir bölümde kalır. Bu yüzden gürültü bulgu listesine girmez.
- Bir aracın sürümü bastırmayı kapatan bir bayrak sunmuyorsa, status dosyası bu kaynağın uygulandığını açıkça yazar.
- SCA komutlarında `--honor-suppressions` yok. OSV-Scanner'ın hedefteki `osv-scanner.toml` dosyası her zaman yok sayılır. Bir test hedefinde bu dosya 66 zafiyetin hepsini gizledi.
- Checkov'un hedefteki yapılandırma dosyası, `--honor-suppressions` ile de yüklenmez. Bu dosya Checkov'a hedefin Python kodunu çalıştırtabilir.
- Trivy 0.75.0 satır içi `trivy:ignore` yorumlarını kapatan bir bayrak sunmuyor. Bu yorumlar Trivy sonuçlarını gizlemeye devam eder. Status dosyası bunu kaydeder.
