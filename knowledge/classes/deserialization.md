---
slug: deserialization
title_en: Insecure deserialization
title_tr: Insecure deserialization
cwe: CWE-502
owasp: A08:2021
sources: sast-skills, codecrucible, open-code-review, deepsec
---

## Summary

The application deserializes attacker bytes with a deserializer that can build types or run code. A crafted payload then triggers a gadget chain and runs arbitrary code, usually full server compromise. The core shape is an untrusted byte stream reaching a code-capable deserializer. A data-only format (JSON, safe YAML, protobuf) is not this class.

## What it is

- **Code-capable deserializers.** Python `pickle.loads`, `marshal.loads`, `yaml.load` without a safe loader, `jsonpickle`; Java `ObjectInputStream.readObject`, `XMLDecoder`, Jackson with default typing, XStream without an allowlist; PHP `unserialize`; Ruby `Marshal.load`, `YAML.load` (Psych) without `permitted_classes`; .NET `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `LosFormatter`; Node.js `node-serialize`, `js-yaml` v3 `load`; Go `encoding/gob`.
- **Gadget chains.** The dangerous classes on the classpath or in the runtime (Commons Collections, Spring, and others) turn a `readObject` into code execution.
- **Untrusted source.** The bytes come from a request body, a cookie, a header, a file upload, a queue message, or a cache the attacker can write.
- **Config that trusts the broker.** Celery with `task_serializer="pickle"` or `accept_content=["pickle"]` trusts every message producer.
- **Custom hooks.** A `__reduce__` method, a JSON reviver, or an `UnmarshalJSON` that runs logic on the payload.

## What it is not

- XML external entity resolution through an XML parser → `xxe`.
- `eval`-style evaluation of attacker source code → `code-injection`.
- JSON prototype pollution through a recursive merge → `prototype-pollution`.
- `JSON.parse`, `yaml.safe_load`, `ast.literal_eval`, protobuf, msgpack: data-only formats with no code semantics. Not this class.

## Where to look

Find the deserializer call. Then trace whether the bytes can come from an untrusted source.

### Python
- `pickle.loads`/`load`, `marshal.loads`, `yaml.load(x)` without `Loader=SafeLoader`, `jsonpickle.decode`, `shelve` with untrusted keys.
- Celery config: `task_serializer`/`accept_content` set to `pickle`.
- Safe: `json.loads`, `yaml.safe_load`.

### Java/Kotlin
- `ObjectInputStream.readObject`/`readUnshared`, `XMLDecoder.readObject`, `XStream.fromXML`, Jackson `enableDefaultTyping()` / `@JsonTypeInfo(use=CLASS)`, Kryo/Hessian without an allowlist.
- Safe: Jackson to a concrete type with no default typing; `ObjectInputFilter` allowlist; XStream `>=1.4.18` with `allowTypes`.

### PHP
- `unserialize($x)` on a cookie, body, or stored value. `allowed_classes` reduces object injection but does not make arbitrary data safe.
- Safe: `json_decode`.

### Ruby
- `Marshal.load`/`restore`, `YAML.load` without `permitted_classes: []`.
- Safe: `JSON.parse`, `YAML.safe_load`.

### Node.js
- `require("node-serialize").unserialize(x)`, `js-yaml` v3 `yaml.load(x)`.
- Safe: `JSON.parse` to plain data (watch prototype pollution separately), `yaml.safeLoad` / yaml 4.x.

### Go
- `encoding/gob` Decode from an untrusted source (the attacker controls types). A custom `UnmarshalJSON` that runs logic.

### C#/.NET
- `BinaryFormatter.Deserialize`, `SoapFormatter`, `NetDataContractSerializer.ReadObject`, `LosFormatter`, `JavaScriptSerializer.Deserialize` with a type resolver.

## Safe patterns

- Use a data-only format for untrusted input: JSON to a concrete type, `yaml.safe_load`, protobuf, msgpack.
- For Java, apply an `ObjectInputFilter` or a strict class allowlist, or avoid native serialization for untrusted bytes.
- Keep Jackson default typing off. Read to a concrete target type.
- Verify an HMAC or signature over the bytes with a server-only key before any deserialize, when a binary format is unavoidable.
- Pin Celery (and similar) to the JSON serializer. Use pickle only with a fully trusted broker.

## Weak mitigations

- A `__proto__`/class blocklist by name. Gadget research finds new chains.
- PHP `allowed_classes`. It narrows object injection but does not make the data trustworthy.
- "The broker is internal". Confirm no web path can write a message. If a producer is reachable, the consumer is a sink.
- A sandbox claim around the deserializer. Treat it as not trusted unless proven.

## Verification checklist

- **attacker_control:** Name the deserializer call and trace the bytes to a request body, cookie, header, upload, queue, or attacker-writable store.
- **privilege_boundary:** State the gain: arbitrary code execution in the process, usually full compromise.
- **unmitigated:** Confirm the deserializer is code-capable and no signature check or class allowlist guards it. Quote `yaml.safe_load`, a concrete-type read, an `ObjectInputFilter`, or a verified HMAC to refute.
- For Java, note any gadget libraries from the architecture summary. Their presence raises exploitability.

## Examples

### Python (pickle)
```python
# Vulnerable: pickle on a request body runs attacker __reduce__
session = pickle.loads(request.get_data())

# Secure: JSON has no code semantics
session = json.loads(request.get_data())
```

### Java/Kotlin (ObjectInputStream)
```java
// Vulnerable: readObject on an untrusted stream -> gadget chain -> RCE
Object obj = new ObjectInputStream(new ByteArrayInputStream(data)).readObject();

// Secure: a data-only format, concrete type, no default typing
MyData obj = new ObjectMapper().readValue(json, MyData.class);
```

### PHP (unserialize)
```php
// Vulnerable: unserialize on a cookie -> POP chain
$user = unserialize(base64_decode($_COOKIE["profile"]));

// Secure: json_decode
$user = json_decode(base64_decode($_COOKIE["profile"]), true);
```

## Dynamic test hints

- Use a local build only. Never send a gadget payload to a real system.
- First confirm the format: send a valid serialized object and a malformed one. A parse error from the deserializer confirms the sink reads your bytes.
- For a proof on a local instance, build a benign gadget (for example one that sleeps) with a tool such as `ysoserial` (Java) or `pickletools`/a `__reduce__` that sleeps (Python), and compare the response time.
- Keep the payload benign (a short sleep) and local. Do not run destructive gadgets.

## False positive traps

- The deserializer is a data-only format: `JSON.parse`, `yaml.safe_load`, protobuf, msgpack, Jackson to a concrete type with no default typing.
- The input comes from a store only server code writes (a server cache, a trusted internal queue) and no client path reaches it.
- The payload is HMAC-signed and the MAC is verified before the deserialize.
- A strict class allowlist or `ObjectInputFilter` is enforced and the allowed classes have no gadget chain.
- The call runs only in a build or CLI path, never on request handling. Mark `unknown` if the caller is outside the source.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-rce/SKILL.md` (MIT, Utku Sen): the deserializer sinks per language, the safe-format patterns, the gadget-chain note, per-stack examples.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-502), `prompts/default/analysis_sections.yaml` (DEPENDENCIES / DESERIALIZATION), `prompts/exploit-proof-web-java/cwe_deep_analysis.yaml` (CWE-502), `prompts/core/audit_families.yaml` (parsing family) (Apache-2.0, Block): the "name the deserializer, trace the bytes" method, Java filters, HMAC-before-deserialize, false positive indicators.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/python.md`, `php.md` (Apache-2.0, alibaba/open-code-review contributors): pickle/yaml.load and PHP `unserialize` rules.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/unsafe-deserialization.ts` (Apache-2.0, Vercel): the JS deserialization and unsafe YAML sinks.
