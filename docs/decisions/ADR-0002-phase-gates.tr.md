# ADR-0002: Faz kapılarında proje sahibinin onayı yerine iç doğrulama
[English](ADR-0002-phase-gates.md) | Türkçe

- **Durum:** Kabul edildi
- **Tarih:** 2026-10-15
- **Karar veren:** proje sahibi
- **Değiştirdiği karar:** ADR-0001'deki "her faz proje sahibinin onayıyla biter" kuralı

## Bağlam

Faz 0 kapısında proje sahibi şuna karar verdi: bütün fazlar onay beklemeden, kontrollü ve iç doğrulamayla ilerlesin. Gerekirse iş paralel ajanlara bölünsün. Proje bütün fazlarıyla eksiksiz bitsin.

## Karar

1. **Faz kapısı = iç kontrol listesi.** Bir faz şu koşullar sağlanınca kapanır:
   - `pytest` bütün testlerle yeşil.
   - `ruff check .` ve `ruff format --check .` temiz.
   - `python scripts/vendor_third_party.py --check` geçiyor.
   - Fazın kabul ölçütü bir demo komutuyla gösterildi ve sonuç değişiklikle birlikte kaydedildi.
2. Kapı geçilince değişiklikler `origin` deposuna gönderilir ve sonraki faz başlar. Proje sahibine kısa bir durum özeti verilir, ama onay beklenmez.
3. **Paralel geliştirme:** Bir fazdaki bağımsız modüller alt ajanlara dağıtılabilir.
   - Her alt ajanın kendine ait, çakışmayan dosyaları var.
   - Alt ajan commit atmaz ve başkasının dosyasını değiştirmez.
   - Birleştiren oturum çıktıyı inceler, tam test setini çalıştırır ve commit atar.
4. Sözleşmeler `docs/ENGINE-SPEC.md` dosyasında durur. Alt ajanlar bu dosyaya uyar.

## Sonuçlar

- Geliştirme onay beklemeden ilerler.
- Kalite güvencesi otomatik kontrollere ve kabul demolarına dayanır.
- Bir kontrol başarısız olursa faz kapanmaz. Hata düzeltilir ve kontrol listesi baştan çalışır.
