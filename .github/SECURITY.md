# Security policy

English | Türkçe below

## Report a vulnerability in kalkan

Do not open a public issue for a vulnerability.

1. Use the private vulnerability report of GitHub: the **Security** tab of this repository, then **Report a vulnerability**.
2. If you cannot use it, write to kalkan@dtechcloud.com. Put "security" in the subject.

Give the kalkan version, the operating system, the steps that show the problem and the impact. We answer within 5 working days and tell you the plan for a fix.

## Scope

In scope: the kalkan engine, the installers, the Claude Code plugin, the Codex files and the PoC sandbox. Of special interest is any way to break the three promises in [docs/SECURITY.md](../docs/SECURITY.md): a change to the audited project, a write by an agent outside its result file, or data that leaves the machine.

Out of scope: vulnerabilities in the scanners that kalkan runs (report them to their projects), and findings that kalkan reports about other code.

## Supported versions

Only the latest release gets security fixes.

---

## kalkan'da bir açık bildir

Bir açık için herkese açık issue açma.

1. GitHub'ın özel açık bildirimini kullan: bu reponun **Security** sekmesi, sonra **Report a vulnerability**.
2. Bunu kullanamıyorsan kalkan@dtechcloud.com adresine yaz. Konuya "security" ekle.

kalkan sürümünü, işletim sistemini, sorunu gösteren adımları ve etkisini yaz. 5 iş günü içinde cevap verir ve düzeltme planını söyleriz.

## Kapsam

Kapsamda: kalkan motoru, kurulum betikleri, Claude Code eklentisi, Codex dosyaları ve PoC sandbox'ı. Özellikle [docs/SECURITY.md](../docs/SECURITY.md) içindeki üç sözü bozan her yol ilgimizi çeker: denetlenen projede bir değişiklik, bir ajanın kendi sonuç dosyası dışına yazması veya makineden çıkan veri.

Kapsam dışında: kalkan'ın çalıştırdığı tarayıcılardaki açıklar (onları kendi projelerine bildir) ve kalkan'ın başka kod hakkında raporladığı bulgular.

## Desteklenen sürümler

Yalnız son sürüm güvenlik düzeltmesi alır.
