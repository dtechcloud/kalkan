# ADR-0006: PoC doğrulama sandbox'ı etkin
[English](ADR-0006-sandbox-active.md) | Türkçe

- Durum: kabul edildi
- Tarih: 2026-10-29
- İlgili: ADR-0004 (bu kararla güncellendi)

## Bağlam

ADR-0004, PoC sandbox'ını v1 kapsamı dışında bıraktı. `poc` aşaması her zaman `poc:skip`
yolunu izledi ve kod bulguları yalnızca statik kanıta dayandı. Proje sahibi 2026-10-29'da
sandbox'ın ana sürüme dahil edilmesini istedi: hedef koddan üretilen küçük bir doğrulama
programı izole bir konteynerde çalışsın, bulgunun gerçek olduğunu göstersin ve kanıtı rapora
eklesin.

## Karar

- `kalkan.sandbox` modülü birim düzeyi doğrulamayı sağlar: `docker_available()` ve
  `run_poc(ctx, task_id, harness)`.
- `poc` aşaması, Docker erişilebilir olduğunda `poc_build` ajan görevlerini ve `poc:run` adımını izler. Docker
  yoksa veya `--docker off` ise eskisi gibi `poc:skip` yolunu izler. Varsayılan `--docker auto`.
- İzolasyon profili (birim düzeyi): ağ yok (`--network none`), salt-okunur kök dosya sistemi,
  root olmayan kullanıcı (65534), bütün yetenekler düşürülür (`--cap-drop ALL`),
  `no-new-privileges`, CPU, bellek (512m) ve PID sınırı, duvar saati zaman aşımı. Hedef
  `/target` altına salt-okunur bağlanır; yalnızca `/out` ve `/tmp` yazılabilir.
- Motor denetim sırasında imaj indirmez. Temel imajlar bir izin listesindedir
  (`src/kalkan/sandbox/images.json`) ve `kalkan sandbox pull` ile elle indirilir. Eksik imaj
  `blocked` olarak raporlanır, indirilmez.
- Kanıt taşıma: konteynerin `/out` çıktısı ve yakalanan günlükler güvenli kopyayla
  `evidence/<bulgu-id>/` altına alınır (bağlantı izlenmez, yalnızca normal dosyalar, boyut ve
  sayı sınırlı).
- Uygulama düzeyi (compose) PoC bu sürümde çalıştırılmaz: `blocked`, blocker
  `sandbox_app_deferred`. Yapı yerinde, sonraki bir çalışmaya bırakıldı.

## Sonuçlar

- `needs_validation` bir kod bulgusu, geçen (`passed`) bir PoC ile `confirmed` olabilir ve
  güven düzeyi `high` olur (`kalkan.findings.merge` kuralları değişmedi).
- `poc.json` durumları: `passed`, `failed`, `blocked`. Blocker kodları: `sandbox_timeout`,
  `sandbox_image_missing`, `sandbox_image_not_allowed`, `sandbox_app_deferred`,
  `sandbox_unavailable`, `sandbox_error`.
- Üç güvenlik sözü korunur (docs/SECURITY.md). Konteynerin ağı yoktur, hedef salt-okunur
  bağlıdır ve PoC sahte veri kullanır. Makineden yalnızca `kalkan sandbox pull` imajları
  indirir (docs/SECURITY.md, "Makineden ne çıkar").
- ADR-0004'ün "v1 kapsamı dışında" ifadesi artık geçmişe aittir. Rapor metni "PoC sandbox bu
  sürümün parçası değil" yerine "PoC doğrulama sandbox'ı bu çalışmada çalışmadı" der.
