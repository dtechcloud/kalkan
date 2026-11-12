---
name: ruby
title: Ruby (Rails, Sinatra, Rack)
tech: ruby, rails
sources: third_party/deepsec/processor/prompt/highlights.ts, third_party/sast-skills/skills/sast-rce/SKILL.md, third_party/sast-skills/skills/sast-sqli/SKILL.md, third_party/sast-skills/skills/sast-xss/SKILL.md, third_party/sast-skills/skills/sast-ssti/SKILL.md, third_party/sast-skills/skills/sast-xxe/SKILL.md, third_party/sast-skills/skills/sast-pathtraversal/SKILL.md, third_party/sast-skills/skills/sast-ssrf/SKILL.md, third_party/sast-skills/skills/sast-fileupload/SKILL.md
---

# Ruby (Rails, Sinatra, Rack)

Rails apps, Sinatra and Grape APIs, Rack middleware, and background jobs. Trace `params` into ActiveRecord string conditions, shell calls, `send`, `constantize`, deserializers, templates, files, and redirects. Check strong parameters on every write and scoping on every lookup. Read `Gemfile.lock` for the Rails and Ruby versions, because many defaults changed between versions.

## Sources of attacker input

- **Rails:** `params` (path, query, and body merged), `request.headers`, `request.env`, `cookies`, `request.body`, `request.raw_post`, uploaded files (`ActionDispatch::Http::UploadedFile`), and Action Cable channel messages.
- **Sinatra, Grape, and Rack:** `params`, `request.body.read`, `env` values, and route captures.
- **Jobs and messages:** Sidekiq and Active Job arguments, Action Mailbox emails, and webhook bodies.
- **Values in params can be strings, arrays, or hashes.** `?id[]=1` or a JSON body changes the type that a condition receives.

## Dangerous sinks

### sqli

- String conditions with interpolation: `where("name = '#{params[:name]}'")`, `find_by_sql("... #{x}")`, `joins("... #{x}")`, `group(x)`, `having(x)`, `pluck(x)`, `lock(x)`, `from(x)`, and `connection.execute("... #{x}")`.
- `order(params[:sort])`: Rails 6.0 and later reject raw SQL in `order` and `pluck` unless code wraps it in `Arel.sql`. Look for `Arel.sql(params[...])`.

### os-command-injection

- `system(string)`, `exec(string)`, `spawn(string)`, backticks, `%x{}`, `IO.popen(string)`, `Open3.capture2(string)`, and `Kernel#open(path)` where `path` starts with `|`, which runs a command. The array forms (`system("convert", file)`) skip the shell.

### code-injection

- `eval`, `instance_eval`, `class_eval`, `module_eval`, and `binding.eval` with input, `send(params[:m])` and `public_send(params[:m])` dispatch, and `params[:type].constantize`, `safe_constantize`, or `Object.const_get(x)` used to pick a class.

### deserialization

- `Marshal.load`, `YAML.load` on Psych before 4.0 (Ruby before 3.1), `YAML.unsafe_load`, `Oj.load` in object mode, and `JSON.load` (which creates objects when `create_additions` is on). Cookie stores that use Marshal with a leaked `secret_key_base` lead to code execution.

### ssti

- `ERB.new(input).result(binding)`, `render inline: input`, Slim or Haml templates built from input, and `Liquid::Template.parse(input)` with custom filters or tags that reach Ruby methods.

### xss

- `raw(x)`, `x.html_safe`, `<%== x %>`, `content_tag` with `html_safe` content, `render html: x.html_safe`, `link_to name, user_url` where the URL can be `javascript:`, and `sanitize` with a wide allowlist. Sinatra ERB templates do not escape unless `escape_html: true` is set.

### path-traversal

- `send_file params[:path]`, `File.read`, `File.open`, `IO.read`, `Rails.root.join("public", params[:f])`, and `Pathname#join` (an absolute argument replaces the base), plus `render file:` or `render params[:template]` with a path from input.

### ssrf

- `Net::HTTP.get(URI(input))`, `URI.open(input)` (open-uri), `HTTParty.get`, `Faraday`, `RestClient`, and `Typhoeus` with a URL from input. `Kernel#open(input)` also opens local files and commands.

### xxe

- `Nokogiri::XML(input) { |config| config.noent }` or `config.dtdload`, and REXML on old versions with entity expansion. Nokogiri's default options do not load external entities.

### open-redirect

- `redirect_to params[:return_to]`, `redirect_to request.referer`, and `redirect_back` with a fallback from input. Rails 7 raises `UnsafeRedirectError` for external hosts when `raise_on_open_redirects` is on (the default for new Rails 7 apps), unless code passes `allow_other_host: true`.

### mass-assignment

- `params.permit!`, `params.to_unsafe_h`, `permit(:role, :admin, :account_id)`, and `update(params[:user])` on code that predates strong parameters.

### missing-authz

- `skip_before_action :authenticate_user!` on write actions, controllers without a Pundit `authorize` call or `verify_authorized`, and CanCanCan controllers without `load_and_authorize_resource`.

### idor

- `Order.find(params[:id])` instead of `current_user.orders.find(params[:id])`, and `find_by(id:)` without a scope.

### csrf

- `skip_forgery_protection`, `protect_from_forgery with: :null_session` on cookie-session controllers, and routes with `via: :all` or GET routes that change state.

### authn

- Format validations with `^` and `$` instead of `\A` and `\z`. Ruby's `^` and `$` match at line breaks, so `"evil\nvalid"` passes. Rails raises an error for such `format:` validations unless `multiline: true` is set.

### crypto

- `rand` or `Random` for tokens, `Digest::MD5` or `Digest::SHA1` for passwords, `==` on secrets, `OpenSSL::Cipher.new("aes-128-ecb")`, and `verify_mode: OpenSSL::SSL::VERIFY_NONE`.

### hardcoded-secrets

- A committed `config/master.key`, `secret_key_base` in `config/secrets.yml`, and API keys in initializers.

### dos-redos

- Regexes with nested quantifiers on input. Ruby 3.2 added memoization against most ReDoS cases and `Regexp.timeout`. Older Ruby versions backtrack without limit.

### sensitive-data-exposure

- `filter_parameters` without password and token keys, `render json: user` that includes `password_digest` or tokens, and detailed exception pages in production (`consider_all_requests_local`).

## Framework notes

### Rails controllers and strong parameters

- `params.require(:user).permit(:name, :email)` is the mass-assignment guard. Assigning `params` without `permit` raises `ForbiddenAttributesError`, so look for `permit!` and broad permit lists.
- `before_action` filters run in order. A `skip_before_action` with `only:` or `except:` can open more actions than intended.

### ActiveRecord

- Hash conditions (`where(name: x)`) and placeholders (`where("name = ?", x)`) bind values. String interpolation does not.
- `find_by_sql`, `exists?` with a string, `calculate`, and the `*_sql` sanitizers used on identifiers are the usual escape hatches.

### Views and ERB

- `<%= %>` escapes. `<%== %>`, `raw`, and `html_safe` do not.
- `html_safe` marks a string as safe. It does not sanitize it.

### Rails configuration

- Check `config.hosts` (host header attacks), `force_ssl`, the content security policy initializer, and `config.action_controller.default_protect_from_forgery`.
- Credentials in `config/credentials.yml.enc` are safe only when `master.key` is not in the repository.

### Sinatra, Grape, and Rack

- Sinatra and Rack have no built-in authentication. A `before` filter or middleware must guard each sensitive route.
- Grape `declared(params)` limits fields to declared ones. Raw `params` passes everything.
- A Rack app mounted inside Rails (`mount Sidekiq::Web`) does not inherit controller filters. It needs a route constraint or its own authentication.

### Background jobs (Sidekiq, Active Job)

- Job arguments come from whoever can enqueue. Re-check ownership inside the job.
- The Sidekiq Web UI needs authentication when it is mounted.

## Safe idioms

- `where(name: x)`, `where("name = ?", x)`, `sanitize_sql_array`, and an allowlist for `order` columns.
- `system("convert", input_path, output_path)` and `Open3.capture2("git", "log", "--", ref)` with array arguments.
- `SecureRandom.hex`, `ActiveSupport::SecurityUtils.secure_compare`, and `has_secure_password` (bcrypt).
- `YAML.safe_load(data, permitted_classes: [])` and `JSON.parse` instead of `JSON.load`.
- `redirect_to url_from(params[:return_to]) || root_path` (Rails 7) or a path allowlist.
- `current_user.orders.find(params[:id])`, Pundit `authorize`, and `after_action :verify_authorized`.
- `File.basename` on uploads, Active Storage with content-type validation, and a check that `File.expand_path(name, base)` starts with `base`.

## Common false positives

- `where("created_at > ?", time)` and other placeholder conditions.
- `order(:name)` and `order(name: :desc)` with symbols or hashes.
- `html_safe` on a constant string, or on output from `sanitize` with the default allowlist.
- `system` with only literal arguments, or with the array form.
- `YAML.load` on Ruby 3.1 or later (Psych 4), which is `safe_load` by default, unless code passes `permitted_classes` that allow dangerous classes.
- `skip_before_action :verify_authenticity_token` on an API controller that authenticates with tokens, not cookies.
- `send` with a symbol from a fixed list.

## Sources

- `third_party/deepsec/processor/prompt/highlights.ts` (Rails, Sinatra, and Grape entries), from vercel-labs/deepsec at commit `4fa6722` (Apache-2.0, Copyright 2026 Vercel, Inc. and contributors).
- `third_party/sast-skills/skills/` (Ruby sink lists in `sast-rce`, `sast-sqli`, `sast-xss`, `sast-ssti`, `sast-xxe`, `sast-pathtraversal`, `sast-ssrf`, and `sast-fileupload`), from utkusen/sast-skills at commit `db52227` (MIT License, Copyright (c) 2026 Utku Sen).
- codecrucible has no Ruby prompt set, and open-code-review has no Ruby rule document. kalkan condensed and rewrote the material above, regrouped it by kalkan class slug, and added version notes.
