# kalkan'a katkı

[English](CONTRIBUTING.md) | Türkçe

Yardımın için teşekkürler. kalkan bir güvenlik aracı. Bu yüzden her değişiklik üç güvenlik sözünü korumalı ([docs/SECURITY.md](docs/SECURITY.md)): denetlenen proje değişmez, ajanlar yalnız kendi sonuç dosyasına yazar, Claude oturumu dışında hiçbir veri makineden çıkmaz.

## Başlamadan önce

- Bir hata için issue aç. kalkan sürümünü (`kalkan --version`), işletim sistemini, komutu ve çıktıyı yaz.
- Yeni bir özellik için önce issue aç ve kullanım durumunu anlat.
- kalkan'da bir açık bulursan issue açma. [SECURITY.md](.github/SECURITY.md) dosyasındaki yolu izle.
- Sana ait olmayan bir projenin kodunu, bulgularını veya raporlarını asla ekleme.

## Değişiklik yap

1. [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) dosyasını oku. Kurulum, kurallar ve kontrol listesi orada.
2. Her pull request'te tek bir değişiklik yap. Testleri ekle veya güncelle.
3. Kontrol listesini çalıştır: `pytest`, `ruff check .`, `ruff format --check .`, `python scripts/vendor_third_party.py --check`, `python scripts/sync_host_files.py --check`, `python scripts/build_plugin.py --check`.
4. Commit mesajını Conventional Commits biçiminde yaz (`feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`).
5. Pull request'i `main` branch'ine aç. Değişikliği, testleri ve kontrol listesinin sonucunu yaz.

`main` en yeni değişiklikleri, `stable` ise kullanıcıların kurduğu denenmiş sürümleri tutar. Merge edilen bir pull request kullanıcılara bir sonraki sürümle ulaşır.

## Kurallar

- Kod, yorumlar, CLI mesajları ve ajan talimatları İngilizce.
- Dokümanlar önce İngilizce yazılır. Türkçe sürüm yanına `<ad>.tr.md` olarak eklenebilir.
- Başka bir projeden kod port edersen lisansını koru: bir SPDX başlığı ve `Ported from <repo>@<commit>: <path>` satırı ekle. [THIRD_PARTY.md](THIRD_PARTY.md) ve [NOTICE](NOTICE) dosyalarını güncelle.
- Yalnız yeniden dağıtıma ve ticari kullanıma izin veren lisanslı içerik ekle. Commons Clause veya Semgrep Rules License altındaki içeriği ekleme.

## Lisans

Katkı verdiğinde, katkın bu reponun MIT lisansıyla ([LICENSE](LICENSE)) lisanslanmış olur.

## Davranış

Saygılı ol. [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/) kurallarına uyarız. Kabul edilemez bir davranışı kalkan@dtechcloud.com adresine bildir.
