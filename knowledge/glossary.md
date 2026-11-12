# Sözlük (glossary)

Bu dosya, Türkçe raporlarda İngilizce kalan teknik terimleri listeler. Her terimin yanında bir satırlık Türkçe açıklama var. Rapor yazan ajan, terimi ilk kullandığı yerde bu açıklamayı bir kez verir, sonra terimi olduğu gibi kullanır.

This file lists the English technical terms that stay in English in Turkish reports. Each term has a one-line Turkish explanation.

## Terimler

### Zafiyet sınıfları (vulnerability classes)

- **SQL injection** — Saldırganın girdisi SQL sorgusuna karışır, sorgu değişir.
- **NoSQL injection** — Saldırgan, MongoDB gibi bir veritabanına operatör veya nesne sokar.
- **XSS (cross-site scripting)** — Saldırganın betiği, başka kullanıcının tarayıcısında çalışır.
- **SSRF (server-side request forgery)** — Sunucu, saldırganın seçtiği adrese istek atar.
- **IDOR (insecure direct object reference)** — Saldırgan, ID değiştirerek başkasının kaydına erişir.
- **BOLA (broken object level authorization)** — IDOR'un API dünyasındaki adı. Nesne sahipliği kontrol edilmez.
- **CSRF (cross-site request forgery)** — Tarayıcı, kullanıcının çerezleriyle istemsiz bir işlem yapar.
- **SSTI (server-side template injection)** — Saldırganın girdisi şablon kaynağı olur, kod çalışır.
- **RCE (remote code execution)** — Saldırgan, sunucuda kendi kodunu çalıştırır.
- **LFI / RFI (local / remote file inclusion)** — Saldırgan, sunucuya yerel veya uzak bir dosya dahil ettirir.
- **path traversal** — Saldırgan, `../` ile hedef dizinin dışına çıkar.
- **open redirect** — Uygulama, kullanıcıyı saldırganın verdiği adrese yönlendirir.
- **prototype pollution** — Saldırgan, JavaScript nesne prototipini kirletir, sonra bir gadget bunu kullanır.
- **mass assignment** — İstek gövdesi, modelin tüm alanlarını (örneğin `is_admin`) doldurur.
- **deserialization** — Güvenilmeyen veri nesneye çevrilir, kod çalışabilir.
- **XXE (XML external entity)** — XML ayrıştırıcı, dış varlık yükler, dosya okur veya SSRF yapar.
- **ReDoS** — Kötü bir regex, küçük girdiyle CPU'yu kilitler.
- **DoS (denial of service)** — Saldırgan, servisi başkalarına kapatır.
- **race condition** — İki işlem aynı anda çalışır, durum bozulur.
- **TOCTOU (time-of-check to time-of-use)** — Kontrol ile kullanım arasında durum değişir.
- **clickjacking** — Saldırgan, bir sayfayı çerçeveye alıp kullanıcıya istemsiz tıklatır.
- **request smuggling** — Ön uç ile arka uç, isteğin sınırını farklı yorumlar.
- **cache poisoning** — Saldırgan, önbelleğe zararlı bir yanıt yazdırır.
- **privilege escalation** — Saldırgan, yetkisini hak etmediği bir seviyeye çıkarır.
- **confused deputy** — Yetkili bir bileşen, yetkisini saldırgan adına kullanır.

### Kavramlar (concepts)

- **payload** — Saldırının taşıdığı asıl veri veya girdi.
- **PoC (proof of concept)** — Zafiyeti güvenli biçimde gösteren küçük kanıt.
- **sink** — Girdinin tehlikeli olduğu son nokta (sorgu, komut, dosya).
- **source** — Saldırganın girdisinin uygulamaya girdiği nokta.
- **taint** — Girdinin "güvenilmez" etiketi. Kaynaktan sink'e kadar izlenir.
- **sanitization** — Girdiyi tehlikesiz hale getirme (temizleme).
- **escaping** — Girdiyi, bağlamı bozmayacak biçimde kaçırma.
- **parameterized query** — Değerleri sorgu metninden ayıran güvenli sorgu.
- **allowlist** — İzin verilenlerin listesi. Güvenli olan yaklaşım.
- **blocklist** — Yasaklananların listesi. Genelde eksik kalır.
- **reachability** — Zafiyetli kodun gerçekten çağrılıp çağrılmadığı.
- **attack surface** — Saldırganın dokunabildiği tüm giriş noktaları.
- **trust boundary** — İki farklı güven seviyesi arasındaki sınır.
- **threat model** — Kimin, neye, nasıl saldırabileceğinin haritası.
- **false positive** — Gerçek olmayan, yanlış alarm bulgu.
- **false negative** — Kaçırılan, bulunamayan gerçek zafiyet.
- **fingerprint** — Bir bulgunun kararlı kimliği. Aynı kök neden hep aynı fingerprint'i alır.
- **hardening** — Zafiyet olmasa da güvenliği artıran iyileştirme.
- **mitigation** — Zafiyetin etkisini azaltan veya durduran önlem.
- **remediation** — Zafiyeti gideren asıl düzeltme.
- **exploit** — Zafiyeti kullanan somut saldırı.
- **gadget** — Tek başına zararsız, ama zincirde kullanılınca zarar veren kod parçası.

### Kimlik ve oturum (identity and session)

- **authentication** — Kimlik doğrulama. "Sen kimsin?"
- **authorization** — Yetkilendirme. "Bunu yapabilir misin?"
- **token** — Kimliği veya yetkiyi taşıyan kısa dize.
- **JWT (JSON Web Token)** — İmzalı, alan taşıyan token biçimi.
- **session** — Sunucunun bir kullanıcıyla sürdürdüğü oturum.
- **cookie** — Tarayıcının sakladığı, isteklerde gönderdiği küçük veri.
- **OAuth** — Üçüncü tarafa sınırlı erişim veren yetki protokolü.
- **OIDC (OpenID Connect)** — OAuth üstüne kurulu kimlik katmanı.
- **SAML** — XML tabanlı federasyon kimlik protokolü.
- **MFA (multi-factor authentication)** — Birden çok kanıtla kimlik doğrulama.
- **passkey / WebAuthn** — Parolasız, cihaza bağlı kriptografik kimlik.
- **mTLS (mutual TLS)** — İki tarafın da sertifikayla doğrulandığı TLS.
- **rate limiting** — İstek hızını sınırlama.
- **brute force** — Deneme yanılmayla parola veya token kırma.
- **replay attack** — Geçerli bir isteği veya imzayı tekrar gönderme.
- **nonce** — Tek kullanımlık sayı. Replay'i önler.
- **CORS (cross-origin resource sharing)** — Tarayıcının kökenler arası erişim kuralı.
- **same-origin policy** — Tarayıcının köken izolasyon kuralı.

### Kriptografi ve sırlar (cryptography and secrets)

- **hash** — Veriden geri döndürülemez özet üretme.
- **salt** — Parola hash'ine eklenen rastgele değer.
- **HMAC** — Anahtarlı mesaj doğrulama kodu.
- **IV (initialization vector)** — Şifrelemede her işlem için gereken rastgele başlangıç değeri.
- **nonce (crypto)** — Kriptografide tekrar kullanılmaması gereken değer.
- **CSPRNG** — Kriptografik olarak güvenli rastgele sayı üreteci.
- **constant-time comparison** — Sırrı, zamanlama sızıntısı olmadan karşılaştırma.
- **key derivation (KDF)** — Paroladan anahtar türetme (argon2, bcrypt, scrypt).
- **secret** — Gizli kalması gereken değer (anahtar, parola, token).
- **hardcoded secret** — Kaynak kodda gömülü sır.

### Araçlar ve standartlar (tools and standards)

- **SAST** — Kaynak kodu çalıştırmadan tarama (statik analiz).
- **SCA (software composition analysis)** — Bağımlılıklardaki bilinen zafiyetleri bulma.
- **SBOM (software bill of materials)** — Yazılımın bağımlılık listesi.
- **CVE** — Bilinen bir zafiyetin genel kimlik numarası.
- **CWE** — Zafiyet türlerinin sınıflandırması.
- **CVSS** — Zafiyet şiddeti puanlama sistemi (0-10).
- **SARIF** — Statik analiz sonuçları için JSON çıktı biçimi.
- **OWASP** — Web güvenliği topluluğu ve listeleri (örneğin Top 10).
- **lockfile** — Bağımlılıkların tam sürümlerini sabitleyen dosya.
- **dependency** — Projenin kullandığı dış paket (bağımlılık).
- **supply chain** — Kaynaktan çalışan ürüne kadar olan tedarik zinciri.
- **webhook** — Bir olayda dış sisteme atılan HTTP çağrısı.
- **middleware** — İstek ile işleyici arasında çalışan ara katman.
- **endpoint** — Bir API veya servisin tek bir erişim noktası.

## Çeviri kuralı (translation rule)

### İngilizce kalır (never translate)

- Yukarıdaki sözlükteki her terim.
- Kod kimlikleri, fonksiyon ve değişken adları, komut sözdizimi, dosya yolları, hata dizileri.
- Araç adları (Trivy, Semgrep, Bandit), standart adları (SARIF, CVSS), CWE ve CVE numaraları.
- Yerleşik protokol ve teknoloji adları (HTTP, TLS, JWT, OAuth, gRPC, GraphQL).
- Sınıf slug'ları (örneğin `sqli`, `missing-authz`). Bunlar motorun kararlı anahtarıdır.

### Türkçeye çevrilir (translate)

- Açıklayıcı düz metin: bulgunun anlatımı, etki, kök neden, düzeltme önerisi.
- Genel fiiller ve isimler: "saldırgan", "yetki", "doğrulama", "sınır", "girdi", "çıktı".
- Başlıklar ve özetler, terimin kendisi hariç.

### Karışık cümle (mixed sentence)

Terim İngilizce kalır, cümlenin geri kalanı Türkçe olur. Terimi ilk kullanımda bir kez kısaca açıkla, sonra olduğu gibi kullan. Örnek: "Bu uç nokta SQL injection içerir. Saldırganın girdisi, sorgu metnine doğrudan eklenir."

## Sources

- Terim listesi ENGINE-SPEC section 3 taksonomisine ve yaygın güvenlik literatürüne dayanır. kalkan bu açıklamaları kendi sözcükleriyle yazdı.
- Çeviri kuralı CLAUDE.md dil kurallarını ve ENGINE-SPEC section 20'yi izler.
