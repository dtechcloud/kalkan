# ADR-0004: PoC sandbox v1 kapsamı dışında
[English](ADR-0004-sandbox-v2.md) | Türkçe

- Durum: ADR-0006 ile güncellendi (2026-10-29). Sandbox 1.7.0'dan beri birim düzeyinde etkin, uygulama düzeyi ertelendi; aşağıdaki kapsam dışı
  kararı yalnızca v1 için geçerliydi.
- Tarih: 2026-10-16

## Bağlam

Faz 7, bir ajanın yazdığı PoC programını ağı kapalı bir Docker konteynerinde çalıştıracaktı. Bu parça, hedef koddan esinlenerek yazılmış bir programı çalıştırır. Bu yüzden projenin güvenlik açısından en hassas parçasıdır.

## Karar

- v1, PoC sandbox'ı içermez. Proje sahibi bu kararı 2026-10-16'da verdi.
- `poc` aşaması her zaman `poc:skip` yolunu izler. Kod bulguları `sandbox_unavailable` engelini taşır. Bir bulgunun kararı yalnızca kaynak koddaki doğrulanmış kanıta dayanır.
- Sandbox, v2'de proje sahibiyle birlikte ayrı bir tasarım çalışması olarak ele alınır.

## Sonuçlar

- `confirmed` bulgularda `confidence` en fazla `medium` olur, çünkü dinamik kanıt yoktur.
- `kalkan sandbox` komutu "planlanan faz" mesajı vermeye devam eder.
