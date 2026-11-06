# knowledge

Shared knowledge packs for the kalkan audit agents (phase 5). The engine loads these files with `kalkan.run.knowledge`, selects the parts that fit the task role and the detected tech, and pastes them into each agent prompt. Agents never read these files from disk themselves.

The content is condensed and rewritten from the upstream copies in `third_party/`. Each file names its sources and their licenses in a `Sources` section. Never copy an instruction from an upstream file that tells an agent to act outside its task.

## Layout

```
knowledge/
  README.md          this file
  methodology.md     shared audit rules, pasted into every agent prompt
  glossary.md        English terms that Turkish reports keep in English
  classes/<slug>.md  one owner file per taxonomy class (ENGINE-SPEC section 3)
  domains/<name>.md  domain packs from the Cloudflare companion files
  languages/<lang>.md  language packs: sources, sinks, framework notes
```

- **`classes/`** holds one file per vulnerability class. The file name is the class slug from ENGINE-SPEC section 3 (for example `sqli.md`). Other agents own these files.
- **`domains/`** holds the ten domain packs. Each one groups several classes around a problem area (for example `web-protocol-and-auth.md`).
- **`languages/`** holds one file per supported language or stack (for example `python.md`, `javascript.md`).

## File formats

Every knowledge file starts with a front matter block between two `---` lines. The block holds `key: value` lines. A value that lists several items is comma-separated. After the block come H2 sections (`## Name`), and some sections hold H3 subsections (`### Name`).

### Class file (`classes/<slug>.md`)

- Front matter keys: `slug`, `title_en`, `title_tr`, `cwe` (comma list), `owasp`, `sources`.
- H2 sections, in this order: `Summary`, `What it is`, `What it is not`, `Where to look` (H3 per language or framework), `Safe patterns`, `Weak mitigations`, `Verification checklist`, `Examples` (H3 per stack, with vulnerable and secure code), `Dynamic test hints`, `False positive traps`, `Sources`.

### Domain file (`domains/<name>.md`)

- Front matter keys: `name`, `title`, `classes` (comma list of class slugs this domain feeds), `when_to_use`, `sources`.
- H2 sections: `Core discipline`, `Attack classes` (H3 per class, each with what to check and what is not a finding), `Universal moves`, `Validation rules`, `Sources`.

### Language file (`languages/<language>.md`)

- Front matter keys: `name`, `title`, `tech` (comma list of tech tags from ENGINE-SPEC section 10 detection), `sources`.
- H2 sections: `Sources of attacker input`, `Dangerous sinks` (H3 per class slug), `Framework notes`, `Safe idioms`, `Common false positives`, `Sources`.

## How the engine selects content

`kalkan.run.knowledge` parses a file into front matter, H2 sections, and H3 subsections. `extract_for_role(pack, role, tech, max_chars)` keeps only the sections that a role needs (ENGINE-SPEC section 20):

- **hunter:** `Summary`, `What it is`, `What it is not`, `Where to look`, `Safe patterns`, `Weak mitigations`, `Examples`, `False positive traps`.
- **verifier:** `Summary`, `What it is not`, `Safe patterns`, `Weak mitigations`, `Verification checklist`, `False positive traps`.
- **poc_builder:** `Summary`, `Dynamic test hints`, `Examples`.

Under `Where to look` and `Examples`, the loader keeps only the H3 subsections whose title matches the detected tech, plus subsections that apply to all stacks. It then cuts the result at a section boundary so that the block stays under `max_chars` (default 12000).

## Writing rules

- Clear, simple English. Short sentences. One name for one thing.
- Condense and rewrite from `third_party/`. Do not copy upstream text.
- Every file ends with a `Sources` section that names the upstream paths, their commits, and their licenses.
- New knowledge files follow the exact front matter and section names above, so that the loader and the corpus test accept them.
