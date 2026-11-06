---
name: php
title: PHP (Laravel, Symfony, WordPress)
tech: php, laravel, symfony
sources: third_party/open-code-review/rules/rule_docs/php.md, third_party/deepsec/processor/prompt/highlights.ts, third_party/sast-skills/skills/sast-rce/SKILL.md, third_party/sast-skills/skills/sast-sqli/SKILL.md, third_party/sast-skills/skills/sast-xss/SKILL.md, third_party/sast-skills/skills/sast-xxe/SKILL.md, third_party/sast-skills/skills/sast-ssti/SKILL.md, third_party/sast-skills/skills/sast-fileupload/SKILL.md, third_party/sast-skills/skills/sast-pathtraversal/SKILL.md, third_party/sast-skills/skills/sast-ssrf/SKILL.md
---

# PHP (Laravel, Symfony, WordPress)

PHP web apps, CMS plugins, and APIs. Trace superglobals and framework request objects into queries, shell functions, `include`, `unserialize`, file functions, templates, and outbound requests. Check loose comparisons in every authentication and authorization decision. Read `composer.json` for the PHP and framework versions before you report version-dependent behavior.

## Sources of attacker input

- **Plain PHP:** `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` (including `name` and `type`), `$_SERVER` values such as `HTTP_*` headers, `REQUEST_URI`, and `PHP_SELF`, `php://input`, and `getallheaders()`.
- **Laravel:** `$request->input()`, `all()`, `query()`, `route()`, `header()`, `cookie()`, `file()`, form request data, and route-model binding keys.
- **Symfony:** `$request->query`, `$request->request`, `$request->attributes`, `$request->headers`, `$request->files`, `getContent()`, and route parameters.
- **WordPress:** `$_GET` and `$_POST` in hooks, `wp_ajax_*` and `wp_ajax_nopriv_*` handlers, REST route callbacks, shortcode attributes, and post meta that other users wrote.
- **Other entry points:** queue job payloads, CLI arguments (`$argv`, Artisan commands), uploaded archives and images, and webhook bodies.

## Dangerous sinks

### sqli

- `mysqli_query`, `$pdo->query`, and `$pdo->exec` with concatenation or interpolation (`"... WHERE id = $id"`), and `$wpdb->query` or `get_results` without `$wpdb->prepare`.
- Laravel `DB::raw`, `whereRaw`, `selectRaw`, `orderByRaw`, `havingRaw`, `DB::statement`, and `DB::select` with interpolated input. Doctrine `createQuery` or `executeQuery` with concatenated DQL or SQL.
- Column names and sort directions from input in `orderBy`, `groupBy`, or `select` need an allowlist.

### os-command-injection

- `exec`, `system`, `passthru`, `shell_exec`, `popen`, `proc_open`, and backticks with input. `escapeshellcmd` still allows argument injection. Use `escapeshellarg` on each argument.
- The fifth `mail()` argument passes options to sendmail.

### code-injection

- `eval`, `assert` with a string (PHP 7), `create_function`, `preg_replace` with the `/e` modifier (PHP 5), `call_user_func` or `$func()` with a name from input, `extract($_GET)` or `parse_str` without a result array (variable overwrite), and `include` or `require` with a path from input.

### deserialization

- `unserialize($input)` (object injection through `__wakeup`, `__destruct`, and gadget chains), and `phar://` paths passed to file functions such as `file_exists` or `getimagesize` (they unserialize phar metadata before PHP 8.0). `allowed_classes => false` blocks object creation but the data stays untrusted.

### path-traversal

- `file_get_contents`, `fopen`, `readfile`, `file_put_contents`, `unlink`, `include`, and `require` with input, Laravel `Storage::get($path)` and `response()->download($path)`, and archive extraction (`ZipArchive::extractTo`) without entry checks. Remote file inclusion also needs `allow_url_include`, which is off by default.

### file-upload

- Extension blocklists that miss `.phtml`, `.phar`, `.php5`, `.php7`, or `.htaccess`, trust in `$_FILES['type']` (the client sets it), the original file name used as the stored name, uploads stored in the web root, and `getimagesize` as the only check (polyglot files pass it).

### ssrf

- `curl_setopt($ch, CURLOPT_URL, $url)`, `file_get_contents($url)` and `fopen($url)` (which also accept `php://`, `data://`, `phar://`, and `file://`), Guzzle, and Symfony HttpClient with a URL from input. `CURLOPT_FOLLOWLOCATION` follows redirects to internal hosts.

### xss

- `echo`, `print`, and `<?= ?>` without `htmlspecialchars`, Blade `{!! $x !!}`, Twig `|raw` or `autoescape false`, Smarty `nofilter`, WordPress output without `esc_html`, `esc_attr`, or `esc_url`, `$_SERVER['PHP_SELF']` in form actions, and `json_encode` inside `<script>` without `JSON_HEX_TAG`.

### ssti

- Twig `createTemplate($input)`, Smarty `fetch('string:' . $input)` or `eval:` resources, `Blade::render($input)`, and `Blade::compileString($input)`.

### xxe

- `simplexml_load_string`, `simplexml_load_file`, `DOMDocument::loadXML`, and `DOMDocument::load` with `LIBXML_NOENT` (which turns entity substitution on) or `LIBXML_DTDLOAD`, and any parser on PHP before 8.0 without `libxml_disable_entity_loader(true)` on old libxml2 versions.

### authn

- Loose comparison in checks: `==` with magic hashes (`"0e123" == "0e456"` is true), `strcmp($array, $secret) == 0` before PHP 8, `in_array` without the strict flag, and `switch` statements on types that juggle.

### crypto

- `rand`, `mt_rand`, `uniqid`, `lcg_value`, or `str_shuffle` for tokens, `md5` or `sha1` for passwords, `==` on secrets or signatures, and `openssl_encrypt` with ECB or a static IV.

### mass-assignment

- `Model::create($request->all())`, `fill($request->all())`, `update($request->all())`, `$guarded = []`, `forceFill`, and Symfony forms with `allow_extra_fields` mapped to entities with role fields.

### missing-authz

- Laravel routes outside the `auth` middleware group or with `withoutMiddleware`, controllers without `$this->authorize`, policies, or gates, Symfony routes without `#[IsGranted]` or `access_control`, and WordPress handlers without `current_user_can`.

### idor

- `Model::find($id)` and `findOrFail($id)` without an owner condition or a policy check, and route-model binding without scoping.

### csrf

- Laravel CSRF exceptions (`VerifyCsrfToken::$except`, or `validateCsrfTokens(except: [...])` in Laravel 11) that include state-changing routes, Symfony forms with `csrf_protection: false`, and WordPress handlers without `check_admin_referer` or `wp_verify_nonce`.

### open-redirect

- `header("Location: " . $_GET['url'])`, `redirect()->to($request->input('next'))`, `redirect()->away($input)`, and `wp_redirect($input)` without `wp_validate_redirect`.

### security-misconfig

- `APP_DEBUG=true` in production (old Ignition versions allow remote code execution), `display_errors=On`, a reachable `.env` file, `phpinfo()` pages, and a committed `APP_KEY`.

### dos-redos

- `preg_*` patterns with nested quantifiers on input. When `preg_match` hits the backtrack limit it returns `false`, and a negative check such as `if (!preg_match(...))` can then pass input that the pattern should block.

## Framework notes

### Laravel

- `routes/web.php` gets sessions and CSRF protection. `routes/api.php` is stateless and needs its own authentication middleware (Sanctum or Passport).
- Eloquent and the query builder bind values. The `*Raw` methods and `DB::raw` do not.
- Blade `{{ }}` escapes. `{!! !!}` does not.
- A leaked `APP_KEY` lets an attacker forge encrypted cookies and signed URLs. Old versions also unserialize cookie values.

### Symfony

- `security.yaml` `access_control` rules match top-down, and the first match wins. A broad early rule defeats a later strict one.
- Twig autoescapes HTML. `|raw` and `{% autoescape false %}` turn it off.
- Voters decide object access. A controller that loads an entity without `denyAccessUnlessGranted` relies on route rules only.

### WordPress

- `wp_ajax_nopriv_*` actions and REST routes with `'permission_callback' => '__return_true'` are public by design. Check what they do.
- A nonce proves intent, not authority. Every privileged handler needs both a nonce check and `current_user_can`.
- `$wpdb->prepare` with placeholders binds values. `esc_sql` alone is weaker and easy to misuse.

### Plain PHP and legacy code

- `register_globals`, magic quotes, and the `/e` modifier are gone in modern PHP. Do not report them for PHP 7 and later.
- `htmlspecialchars` escapes single quotes by default only since PHP 8.1. Older code needs `ENT_QUOTES` for single-quoted attributes.
- `$_REQUEST` mixes GET, POST, and cookies, so a cookie can override a form field.

### Other frameworks (CodeIgniter, Yii, CakePHP, Slim, Drupal)

- CodeIgniter filters, Yii `behaviors()` access rules, CakePHP `Auth->allow()` lists, Slim `->add()` middleware, and Drupal `_permission` route requirements are the auth gates. Routes outside them are public.
- Raw query calls (`$db->query("...$x")`, `createCommand("...$x")`, `db_query("... $x")`) are the injection sinks in each framework.

## Safe idioms

- PDO prepared statements (`$stmt = $pdo->prepare('... WHERE id = :id'); $stmt->execute(['id' => $id]);`), Eloquent and query builder bindings, and `$wpdb->prepare`.
- `escapeshellarg` on each argument, or `proc_open` with an argument array (PHP 7.4+).
- `htmlspecialchars($s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')`, Blade `{{ }}`, Twig autoescape, and WordPress `esc_*` functions.
- `json_decode` instead of `unserialize` for client data.
- `random_bytes`, `random_int`, `password_hash`, `password_verify`, and `hash_equals`.
- `realpath()` followed by a prefix check against the base directory, and `basename()` on upload names with a generated stored name.
- `===` and `in_array($v, $list, true)` for security decisions.
- `$fillable` lists or validated arrays (`$request->validated()`) for mass assignment.

## Common false positives

- Interpolated SQL whose values are cast with `(int)` or come from constants.
- `unserialize` on data that the server signed with `hash_hmac` and verified with `hash_equals` before the call, or on trusted cache entries that only the server writes.
- `echo` of values that the code already passed through `htmlspecialchars` or `esc_html`.
- `{!! !!}` with output from a sanitizer such as HTMLPurifier, or with static HTML.
- `md5` for cache keys or file checksums.
- `$_SERVER['REMOTE_ADDR']` used for logging only.
- CSRF exceptions for webhook routes that verify a provider signature.
- `wp_ajax_nopriv_` handlers that return public data only.

## Sources

- `third_party/open-code-review/rules/rule_docs/php.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors).
- `third_party/deepsec/processor/prompt/highlights.ts` (Laravel, Symfony, WordPress, Slim, Yii, CakePHP, CodeIgniter, and Drupal entries), from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- `third_party/sast-skills/skills/` (PHP sink lists in `sast-rce`, `sast-sqli`, `sast-xss`, `sast-xxe`, `sast-ssti`, `sast-fileupload`, `sast-pathtraversal`, and `sast-ssrf`), from utkusen/sast-skills at commit `db52227` (MIT License, Copyright (c) 2026 Utku Sen).
- codecrucible has no PHP prompt set. kalkan condensed and rewrote the material above, regrouped it by kalkan class slug, and added version notes.
