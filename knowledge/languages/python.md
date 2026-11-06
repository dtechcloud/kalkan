---
name: python
title: Python (Django, Flask, FastAPI)
tech: python, django, flask, fastapi
sources: third_party/codecrucible/prompts/exploit-proof-web-python/analysis_sections.yaml, third_party/codecrucible/prompts/exploit-proof-web-python/cwe_deep_analysis.yaml, third_party/open-code-review/rules/rule_docs/python.md, third_party/deepsec/processor/prompt/highlights.ts, third_party/sast-skills/skills/sast-rce/SKILL.md
---

# Python (Django, Flask, FastAPI)

Python web apps, APIs, workers, and tools. Trace request data into every ORM escape hatch, template, subprocess, file, deserializer, and outbound request. Check every view for authentication and every object lookup for ownership.

## Sources of attacker input

- **Django:** `request.GET`, `request.POST`, `request.body`, `request.FILES`, `request.COOKIES`, `request.headers`, `request.META` (including `HTTP_X_FORWARDED_*`), URL converters (`<str:slug>`, `<path:p>`), and DRF `request.data` and `request.query_params`.
- **Flask:** `request.args`, `request.form`, `request.values`, `request.json`, `request.get_json()`, `request.files`, `request.cookies`, `request.headers`, and view arguments from `<name>` route parts.
- **FastAPI and Starlette:** `Path`, `Query`, `Body`, `Header`, `Cookie`, `Form`, and `File` parameters, `request.query_params`, `await request.json()`, `await request.form()`, and WebSocket messages.
- **Other entry points:** Celery and RQ task arguments, queue consumers (Kafka, SQS, Redis streams), webhook bodies, GraphQL resolver arguments (Graphene, Strawberry), CLI arguments (`sys.argv`, `argparse`, `click`), and parsed files (archives, images, YAML, XML, pickles).
- Values that a user stored earlier in the database, cache, or files are second-order input.

## Dangerous sinks

### sqli

- `cursor.execute(f"...")`, `cursor.execute("..." % v)`, `cursor.execute("...".format(v))`, and `cursor.execute("..." + v)`.
- Django `Model.objects.raw(f"...")`, `.extra(where=[...])`, and `RawSQL(f"...")`.
- SQLAlchemy `text(f"...")`, `session.execute(f"...")`, `literal_column(user)`, and `order_by(text(user))`.
- Identifiers (column, table, `ORDER BY` direction) from input. Parameters cannot bind identifiers, so they need an allowlist.

### nosqli

- PyMongo `find(request.json)`, or a filter value that can be a dict with operators (`{"$ne": None}`), and `$where` with input.

### os-command-injection

- `os.system`, `os.popen`, any `subprocess` function with `shell=True`, and `asyncio.create_subprocess_shell`.
- Argument injection: a list command with a user value that starts with `-` (for example `["git", "clone", url]` where `url` is `--upload-pack=...`).

### code-injection

- `eval`, `exec`, and `compile` on input, `__import__(name)`, `importlib.import_module(name)`, and `getattr(module, name)()` dispatch on input.

### ssti

- `render_template_string(user)`, `jinja2.Template(user)`, `Environment().from_string(user)`, Mako `Template(user)`, and Django `Template(user)`. The template source is the problem, not the context values. The Jinja2 sandbox does not make it safe. Django templates cannot call arbitrary Python, so their impact is usually data disclosure.

### deserialization

- `pickle.loads` and `pickle.load`, `dill`, `joblib.load`, `pandas.read_pickle`, `numpy.load(..., allow_pickle=True)`, `torch.load` with `weights_only=False` (the default before PyTorch 2.6), `marshal.loads`, `shelve.open`, and `jsonpickle.decode`.
- `yaml.load` without `SafeLoader`, `yaml.unsafe_load`, and `yaml.load(..., Loader=yaml.Loader)`.
- Celery with `task_serializer="pickle"` or pickle in `accept_content`, when less trusted producers can reach the broker.

### path-traversal

- `open`, `send_file`, `FileResponse`, `shutil.copy`, `shutil.rmtree`, and `os.remove` with input.
- `os.path.join(base, user)` does not stop `../`, and an absolute `user` replaces `base`.
- `tarfile.extractall()` without `filter="data"` (the default before Python 3.14), `shutil.unpack_archive()` on tar files, and hand-written zip extraction that joins `member.filename` to a directory.

### ssrf

- `requests`, `httpx`, `urllib.request.urlopen` (which also opens `file://`), `aiohttp.ClientSession`, `urllib3`, and `pycurl` with a URL from input. `requests` follows redirects by default.

### xss

- Django `mark_safe(user)`, `|safe`, `{% autoescape off %}`, and `format_html` with a pre-built string as the format.
- Jinja2 `Markup(user)`, `|safe`, and an `Environment()` without `autoescape` (the plain Jinja2 default is off). Flask autoescapes only `.html`, `.htm`, `.xml`, `.xhtml`, and `.svg` templates.
- `HttpResponse(user)` and `HTMLResponse(user)` with an HTML content type. A value inside `<script>` needs `json_script` or JSON encoding, not HTML escaping.

### xxe

- lxml parsers with `resolve_entities=True` (the default before lxml 5.0) or `no_network=False`, and `xml.sax` with the `feature_external_ges` feature on. The standard library parsers do not fetch external entities by default.

### file-upload

- `f.save(os.path.join(UPLOAD_DIR, f.filename))` without `secure_filename`, uploads stored in a served static directory, and type checks that trust `Content-Type` or the extension only.

### open-redirect

- `redirect(request.args["next"])` and `HttpResponseRedirect(request.GET["next"])` without `url_has_allowed_host_and_scheme`.

### mass-assignment

- `Model.objects.create(**request.POST.dict())`, `obj.__dict__.update(data)`, a `setattr` loop over request keys, `ModelForm` or DRF serializers with `fields = "__all__"`, and Pydantic models with `extra="allow"` copied into ORM rows.

### missing-authz

- Views without `@login_required`, `LoginRequiredMixin`, DRF `permission_classes`, or a FastAPI auth dependency. DRF `AllowAny` on a sensitive viewset.

### idor

- `get_object_or_404(Order, pk=pk)` without `user=request.user`, and DRF viewsets whose `queryset` is `Model.objects.all()` with no filtering `get_queryset`.

### csrf

- `@csrf_exempt` on state-changing views, a middleware list without `CsrfViewMiddleware`, Flask cookie sessions without CSRF protection, and GET views that change state.

### crypto

- `random` for tokens, `hashlib.md5`, `sha1`, or a bare SHA-256 for passwords, `==` on secrets, AES in ECB mode or with a static IV, `requests(..., verify=False)`, and `ssl._create_unverified_context()`.

### jwt

- `jwt.decode(token, options={"verify_signature": False})`, a missing `algorithms` list, and one key accepted for both HMAC and RSA algorithms.

### hardcoded-secrets

- `SECRET_KEY`, `app.secret_key`, database URLs, and cloud keys in committed settings files.

### security-misconfig

- `DEBUG = True` or `ALLOWED_HOSTS = ["*"]` in a settings module that production loads, `SESSION_COOKIE_SECURE = False`, and `CORS_ALLOW_ALL_ORIGINS = True` with credentials.

### dos-redos

- `re` patterns with nested quantifiers on input, no body size limit, decompression without an output cap, and blocking calls inside `async def` handlers.

### race-condition

- Check-then-act updates (`if balance >= amount: balance -= amount`) without `select_for_update()`, `transaction.atomic()`, or an `F()` expression.

### sensitive-data-exposure

- Logs of request bodies, headers, or tokens, FastAPI routes without `response_model` that return whole ORM rows, and Django debug pages.

## Framework notes

### Django

- Querysets parameterize values. The escape hatches are `raw()`, `extra()`, and `RawSQL`.
- Templates autoescape. The escape hatches are `|safe`, `mark_safe`, and `autoescape off`.
- CSRF middleware is on by default. Look for `@csrf_exempt` and for middleware lists without it.
- `DEBUG = True` shows settings and tracebacks. Check which settings module production uses.

### Django REST Framework

- Without `DEFAULT_PERMISSION_CLASSES` in settings, the default permission is `AllowAny`.
- `SessionAuthentication` enforces CSRF only for authenticated requests. Token authentication needs no CSRF token.
- `@action` methods inherit the viewset permissions unless they override them.

### Flask

- Flask has no built-in authentication. Each sensitive view needs a decorator such as `@login_required` below `@app.route`.
- `send_from_directory` uses a safe join. Custom helpers built on `os.path.join` do not.
- `app.secret_key` signs the session cookie. A known key lets an attacker forge sessions.

### FastAPI and Starlette

- Authentication lives in dependencies (`Depends(...)`). A route without one is public. Check router-level `dependencies=[...]` too.
- A sub-application mounted with `app.mount()` does not get the parent's global dependencies.
- Pydantic validates types, not authorization. `dict`, `Any`, and `extra="allow"` fields accept arbitrary keys.
- Blocking calls in `async def` routes stall the event loop for every user.

### Celery and task queues

- Tasks run with worker trust and no request user. Re-check ownership inside a task that acts on user data.
- The serializer decides the deserialization risk. JSON is safe. Pickle trusts every producer that can reach the broker.

## Safe idioms

- `cursor.execute("SELECT ... WHERE id = %s", (user_id,))` and ORM filters with values.
- `subprocess.run(["convert", "--", path], shell=False, check=True)` with an allowlisted program.
- `secrets.token_urlsafe()`, `hmac.compare_digest()`, and Django password hashers, `argon2-cffi`, or `bcrypt`.
- `yaml.safe_load`, `json.loads`, `defusedxml`, and `tarfile.extractall(filter="data")`.
- `Path(base, name).resolve().is_relative_to(base.resolve())` before an open, `werkzeug.utils.secure_filename`, and `werkzeug.security.safe_join`.
- `url_has_allowed_host_and_scheme(url, allowed_hosts={request.get_host()})` before a redirect.
- Explicit serializer and form field lists, and Pydantic `ConfigDict(extra="forbid")`.
- `select_for_update()` inside `transaction.atomic()`, or one `update()` with `F("balance") - amount`.

## Common false positives

- `cursor.execute("... %s", (value,))` passes parameters. Only a `%` operator between the string and the value builds SQL text.
- f-string SQL that interpolates only constants, or a value already converted by `int()` or an `<int:pk>` converter.
- `subprocess.run([...])` with a list and no `shell=True`, unless a value can start with `-`.
- `yaml.load(data, Loader=yaml.SafeLoader)`, and `pickle` on data that the server signed and verified with HMAC before the load.
- `mark_safe` on a constant string or on `format_html` output with arguments.
- `hashlib.md5` or `sha1` for cache keys, ETags, or file deduplication, and `random` for sampling, jitter, or tests.
- `@csrf_exempt` on a webhook view that verifies a provider signature, or on a token-authenticated API.
- `DEBUG = True` in a development settings file that production does not load. If the deployed module is unknown, the claim is `needs_validation`.
- `eval` or `pickle` in tests, migrations, or management commands that only operators run.

## Sources

- `third_party/codecrucible/prompts/exploit-proof-web-python/analysis_sections.yaml` and `cwe_deep_analysis.yaml`, from block/codecrucible at commit `b5c8086` (Apache-2.0, Copyright 2026 Block, Inc.).
- `third_party/open-code-review/rules/rule_docs/python.md`, from alibaba/open-code-review at commit `11ac6d4` (Apache-2.0, Copyright 2026 alibaba/open-code-review contributors).
- `third_party/deepsec/processor/prompt/highlights.ts` (Django, Django REST Framework, FastAPI, Flask, Starlette, and Celery entries), from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- `third_party/sast-skills/skills/sast-rce/SKILL.md` (Python sink lists), from utkusen/sast-skills at commit `db52227` (MIT License, Copyright (c) 2026 Utku Sen).
- kalkan condensed and rewrote the material, regrouped it by kalkan class slug, and added version notes.
