---
slug: sqli
title_en: SQL injection
title_tr: SQL injection
cwe: CWE-89, CWE-90, CWE-643
owasp: A03:2021
sources: sast-skills, codecrucible, deepsec, open-code-review, security-audit-skill
---

## Summary

The application builds a query string with attacker text instead of a bound parameter. The attacker then changes the query logic: read other rows, bypass a login, write or delete data, and in some databases run OS commands. This class also covers injection into other query languages: LDAP and XPath. The core shape is string building that reaches a query sink.

## What it is

- **String concatenation into a query.** `"... WHERE id = '" + id + "'"` or `f"... WHERE name = '{name}'"`.
- **Format functions.** `.format()`, `%` formatting, `fmt.Sprintf`, `String.format`, `sprintf` used to build the query text.
- **ORM raw escape hatches.** Django `.raw()`, `.extra()`, `RawSQL`; SQLAlchemy `text(f"...")`; Sequelize `query(`...${x}...`)`; TypeORM `.query("..."+x)`; Prisma `$queryRawUnsafe`; Rails `where("col = '#{x}'")`, `find_by_sql`; MyBatis `${param}`; Go GORM `.Raw(fmt.Sprintf(...))`; EF Core `FromSqlRaw($"...{x}...")`.
- **Dynamic identifiers.** A column name, table name, `ORDER BY`, `GROUP BY` or `LIMIT` from user input. A placeholder cannot bind an identifier, so only an allowlist helps.
- **Second-order.** Input is stored with a bound parameter, then read back and concatenated into a new query without binding.
- **Other query languages.** LDAP filter strings with unescaped `( ) * \` (CWE-90). XPath expressions built with user text (CWE-643).

## What it is not

- MongoDB operator injection (`$ne`, `$where`) → `nosqli`.
- OS command through `xp_cmdshell` or a shell → `os-command-injection`.
- `eval`-style evaluation of attacker code → `code-injection`.
- A stored `<script>` that renders unescaped later → `xss`.
- Changing `?id=1` to `?id=2` to reach another row with a safe query → `idor`.
- Setting extra model fields from the body → `mass-assignment`.

## Where to look

Find the query sink first. Then check whether the value arrives as a bound parameter or as part of the string.

### Python
- `cursor.execute(f"...")`, `% ` or `.format()` in the SQL, `connection.execute(sql_string)`.
- Django `.raw()`, `.extra()`, `RawSQL`; SQLAlchemy `text(f"...")`, Peewee `RawQuery`.
- Safe shape: `cursor.execute("... %s", (val,))`, `text("... :x").bindparams(x=val)`.

### JavaScript/TypeScript
- Template-literal SQL: `` db.query(`... ${x}`) ``; `knex.raw(x)`; `sequelize.query` without `replacements`; TypeORM `.query`.
- Prisma: tagged `$queryRaw`...`` is parameterized and safe; `$queryRawUnsafe` and `Prisma.raw` are not.

### Java/Kotlin
- JDBC/JdbcTemplate with `"..."+x`; Hibernate `createQuery("..."+x)`, `createNativeQuery("..."+x)`.
- MyBatis mappers: `${param}` interpolates (unsafe), `#{param}` binds (safe). See `mapper_dao_xml` notes.
- Safe shape: `PreparedStatement` with `?`, `createQuery("... :x").setParameter("x", val)`, positional `?1`, Criteria API.

### Go
- `db.Query(fmt.Sprintf(...))`, `db.Exec(q + x)`, GORM `.Where("col = "+x)`, `.Raw(fmt.Sprintf(...))`.
- Safe shape: `db.Query("... WHERE id = $1", x)`, GORM `.Where("col = ?", x)`.

### PHP
- `$pdo->query("..." . $x)`, `mysqli_query("..."+$x)`, Doctrine `executeQuery("..."+$x)`, Laravel `DB::raw`, `whereRaw`, `selectRaw` with interpolation.
- Safe shape: `$pdo->prepare("... :id")->execute(['id'=>$x])`.

### Ruby
- `where("name = '#{x}'")`, `find_by_sql("..."#{x})`, `Sequel.lit`.
- Safe shape: `where("name = ?", x)`, `where(name: x)`.

### C#/.NET
- `new SqlCommand("..."+x)`, Dapper `Query("..."+x)`, EF Core `FromSqlRaw($"...{x}...")`.
- Safe shape: `SqlCommand` with `@p` plus `Parameters.AddWithValue`, EF Core `FromSqlInterpolated($"...{x}...")`.

## Safe patterns

- A prepared statement or placeholder (`?`, `$n`, `:name`) with the values in a separate argument list.
- An ORM query builder method (`.filter`, `.where(col: val)`, `.find`) with no raw string.
- An allowlist that checks a dynamic identifier against a fixed set before it reaches the query.
- A value coerced to a non-string type (integer, UUID, enum) that rejects malformed input, for a numeric position only.

## Weak mitigations

- Custom escaping (`mysql_real_escape_string`, `addslashes`, a homegrown sanitizer). It is not equal to a bound parameter and has a bypass history. Keep the finding.
- A blocklist of keywords such as `UNION` or `--`. An attacker works around it.
- A type cast for a quoted string position. It helps a numeric position only.
- A placeholder in the string but the same value also concatenated. Read both the string and the argument list.

## Verification checklist

- **attacker_control:** Name the entry point and the request. Quote the line that concatenates or formats the value into the SQL, not a nearby placeholder call.
- **privilege_boundary:** State the gain: read another user's rows, bypass the login, or write data the position does not allow.
- **unmitigated:** Confirm the value enters as a string part, not a bound parameter. For an identifier position, confirm no allowlist. Quote the binding call or the allowlist to refute.
- Second-order: when the value is read from the database, trace the write to confirm it started as user input.

## Examples

### Python
```python
# Vulnerable: f-string into the query
cur.execute(f"SELECT * FROM users WHERE name = '{request.args['name']}'")

# Secure: bound parameter
cur.execute("SELECT * FROM users WHERE name = %s", (request.args["name"],))
```

### JavaScript/TypeScript
```javascript
// Vulnerable: template literal in the query text
db.query(`SELECT * FROM orders WHERE status = '${req.query.status}'`);

// Secure: placeholder binding
db.query("SELECT * FROM orders WHERE status = $1", [req.query.status]);
```

### Java/Kotlin
```java
// Vulnerable: concatenation into JdbcTemplate
jdbc.queryForObject("SELECT * FROM users WHERE name = '" + name + "'", mapper);

// Secure: bound parameter
jdbc.queryForObject("SELECT * FROM users WHERE name = ?", mapper, name);
```

### Dynamic identifier (all stacks)
```python
# Vulnerable: ORDER BY from user input (a placeholder cannot bind it)
cur.execute(f"SELECT * FROM products ORDER BY {request.args['sort']}")

# Secure: allowlist before use
ALLOWED = {"name", "price", "created_at"}
col = request.args["sort"]
if col not in ALLOWED:
    abort(400)
cur.execute(f"SELECT * FROM products ORDER BY {col}")
```

## Dynamic test hints

- Use a local build only. Never run a test against a real system.
- First confirm the sink responds to a single quote: send `name=O'Brien` and look for a 500 or a SQL error.
- Then test boolean logic: `name=x' OR '1'='1` against a non-production database.
- For a time test on a local database: `name=x'; SELECT pg_sleep(3)-- ` and compare the response time.
- `sqlmap` against a local instance only: `sqlmap -u "http://127.0.0.1:8000/search?q=test" -p q --batch`. Never point it at a real host.
- For an identifier position, try `sort=name;DROP` and confirm the allowlist rejects it.

## False positive traps

- The value reaches the query through a placeholder with a separate argument list.
- The value is coerced to an integer, UUID or enum before the query, and the coercion rejects bad input.
- The concatenated part is a server-chosen literal (a static alias, a fixed schema prefix) with no attacker bytes.
- The query is built by an ORM builder chain with no raw escape hatch on this path.
- Prisma tagged-template `$queryRaw`...`` auto-parameterizes. Only `$queryRawUnsafe` and `Prisma.raw` concatenate.
- MyBatis `#{param}` binds. Only `${param}` interpolates.

## Sources

Condensed and rewritten from the local copies under `third_party/`.

- `utkusen/sast-skills@db52227: sast-files/.claude/skills/sast-sqli/SKILL.md` (MIT, Utku Sen): the IS / IS NOT blocks, prevent patterns, per-stack examples, identifier and second-order notes.
- `block/codecrucible@b5c8086: prompts/default/cwe_deep_analysis.yaml` (CWE-89), `prompts/default/analysis_sections.yaml` (INJECTION), `prompts/core/audit_families.yaml` (injection family), `prompts/exploit-proof-web-*` (Apache-2.0, Block): validation checks, false positive indicators, per-language sinks.
- `vercel-labs/deepsec@4fa6722: packages/scanner/src/matchers/sql-injection.ts`, `prisma-raw-sql.ts`, `drizzle-raw-sql.ts`, `soql-injection.ts`, `processor/src/prompt/slug-notes.ts` (Apache-2.0, Vercel): raw-SQL escape-hatch notes per ecosystem.
- `alibaba/open-code-review@11ac6d4: internal/config/rules/rule_docs/python.md`, `php.md`, `go.md`, `mapper_dao_xml.md` (Apache-2.0, alibaba/open-code-review contributors): MyBatis `${}` vs `#{}`, identifier allowlist rule.
- `cloudflare/security-audit-skill@c1c8a8c: skills/security-audit/ATTACK-CLASSES.md` (MIT, Cloudflare): injection trace method, LDAP/XPath as secondary query sinks.
