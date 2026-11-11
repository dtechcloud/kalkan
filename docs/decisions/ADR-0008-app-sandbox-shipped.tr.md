# ADR-0008: Uygulama düzeyi PoC sandbox'ı etkin
[English](ADR-0008-app-sandbox-shipped.md) | Türkçe

- Durum: kabul edildi
- Tarih: 2026-11-11
- Karar veren: proje sahibi
- İlgili: ADR-0001, ADR-0004 ve ADR-0006 (bu karar onların "uygulama düzeyi ertelendi" kısımlarının yerini alır)

## Bağlam

ADR-0006, PoC sandbox'ını birim düzeyinde etkinleştirdi ve uygulama düzeyini (compose yığınları) erteledi. Uygulama düzeyi artık motorda var: `kalkan.sandbox.app` (docs/ENGINE-SPEC.md, bölüm 23). Bazı bulgular çalışan uygulamayı ister, örneğin bir IDOR veya eksik bir yetki kontrolü. Birim düzeyi bir harness bunları gösteremez.

## Karar

- Uygulama düzeyi etkin. `poc_build` sonucu bunu isterse motor hedefin compose yığınını başlatır ve harness isteklerini bir istemci konteynerinden gönderir.
- Motor önce çözülmüş compose yapılandırmasını kontrol eder. Şunları reddeder: ayrıcalıklı servis, host veya paylaşılan namespace, eklenen yetenek, cihaz, Docker soketi, hedef kopyasının dışına bind mount, harici volume veya ağ (blocker `sandbox_app_unsafe`).
- Motor kendi compose dosyasını yazar. Her servis internet erişimi olmayan tek bir iç ağdadır. Hiçbir port host'a açılmaz. Servisler küçük bir yetenek seti, `no-new-privileges` ve bellek, CPU ve PID sınırları alır. Hedef kopyasının içindeki bind'lar salt okunurdur.
- Uygulama düzeyi ağı yalnızca isteğe bağlı `--allow-build-network` ile kullanır (`kalkan audit --allow-build-network` veya `kalkan run init --allow-build-network`). Bayrak varsayılan olarak kapalıdır. Bayrak açıksa `docker compose pull` ve `docker compose build`, yığın imajlarını çekmek ve derlemek için ağ erişimi alır. Çalışan yığın iç ağda kalır ve internete hiç çıkmaz.
- Bayrak olmadan motor hiçbir imaj çekmez ve derlemez. İmaj isteyen bir bulgu `sandbox_build_network_needed` veya `sandbox_image_missing` blocker'ıyla `blocked` olur.
- Sonda her zaman `docker compose down -v --remove-orphans --rmi local` çalışır.

## Sonuçlar

- Rapor, çalışan uygulamayı isteyen bulgular için çalışma zamanı kanıtı gösterebilir.
- docs/SECURITY.md, `--allow-build-network` bayrağını ağı kullanan isteğe bağlı özellikler arasında listeler.
- `sandbox_app_deferred` blocker'ı raporda okunabilir kalır, ama motor onu artık yazmaz.
