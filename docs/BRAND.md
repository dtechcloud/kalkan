# Brand

This page holds the kalkan identity: the name, the slogan, the logo, the colors and the type. The files are in [brand/](brand/). `scripts/build_brand_assets.py` builds them.

## Name

Write kalkan in lowercase, also at the start of a sentence. kalkan is the Turkish word for "shield".

## Slogan

| Line | Text |
|---|---|
| Slogan | Last stop before production. |
| Turkish | Canlıya çıkmadan önce son durak. |
| Descriptor | Security audit for source code, inside Claude Code. |
| Proof line | Every confirmed finding quotes its source. The scans stay on your machine. |

The proof line says "confirmed" because only the findings that the agents verify carry quotes. A `--tools-only` run gives unverified tool results. "The scans stay on your machine" is exact: the scanners and the SCA run offline, and only the traffic of your own Claude session leaves the machine ([SECURITY.md](SECURITY.md)).

## Logo

The logo is the word kalkan and a full stop in the shape of a shield. In English, the period is also a "full stop": the last stop of a sentence. The full stop has the accent color. The mark is the k of the logo with the same full stop.

| File | Use |
|---|---|
| [kalkan-logo-dark.svg](brand/kalkan-logo-dark.svg) | Logo on a dark background |
| [kalkan-logo-light.svg](brand/kalkan-logo-light.svg) | Logo on a light background |
| [kalkan-mark-dark.svg](brand/kalkan-mark-dark.svg), [kalkan-mark-light.svg](brand/kalkan-mark-light.svg) | Mark, where the logo does not fit |
| [kalkan-icon.svg](brand/kalkan-icon.svg) | App icon and favicon: the mark on a dark tile |
| [kalkan-banner-dark.svg](brand/kalkan-banner-dark.svg), [kalkan-banner-light.svg](brand/kalkan-banner-light.svg) | README banner, 1280 × 400 |

- Keep free space around the logo. The free space is at least the width of the k.
- Use the logo at 64 px wide or more. Below that size, use the mark. Use the mark at 16 px or more.
- Do not change the colors, the letter spacing or the shape of the full stop. Do not add a shadow or an outline.
- In plain text, write kalkan without the full stop.

## Colors

The look is dark first: a near-black ground, off-white text and thin lines. A light theme uses the same tokens. The accent is Sinyal, a signal orange. Use the accent in one place per view: the full stop, the shell prompt `❯` or a selected state.

| Token | Dark theme | Light theme | Use |
|---|---|---|---|
| Ground | `#0A0A0A` | `#FAFAF8` | Page background |
| Surface | `#121211` | `#FFFFFF` | Raised areas |
| Heading | `#F7F6F3` | `#0A0A0A` | Headings, logo |
| Text | `#C9C7C2` | `#3B3A37` | Running text |
| Quiet | `#8F8D87` | `#6C6A65` | Labels, secondary text |
| Faint | `#5E5C58` | `#A19F9A` | Hints |
| Line | `#FFFFFF` at 10 % | `#0A0A0A` at 10 % | Thin lines |
| Accent (Sinyal) | `#FF7A1A` | `#C2540A` | Full stop, prompt, selection |

The light theme uses a darker accent. On the light ground it has a contrast of 4.4:1: use it for marks, icons and text of 18 px or more. The status colors (pass, fail) and the severity colors of the reports are not accents.

## Type

| Role | Face | Setting |
|---|---|---|
| Logo | Geist 600 | Lowercase, letter spacing −0.045 em |
| Headings | Geist 600 | Letter spacing −0.04 em |
| Text | Geist 400 | 16 px, line height 1.6 |
| Code and labels | Geist Mono 400 and 500 | Labels in capitals, letter spacing 0.14 em |

Geist and Geist Mono have the SIL Open Font License 1.1. The SVG files carry the letters as outlines, so a viewer needs no font.

The HTML reports (`REPORT.html`, `EXECUTIVE.html`) use the theme "Gece" (`src/kalkan/report/theme.py`): the dark tokens of the site first, its light tokens with the theme toggle or a light system setting, and the light tokens in print. They embed subsets of both fonts (`scripts/build_report_fonts.py`) and the logo as data URIs, so a report needs no network.

## Look

Two thin rails frame the page. A small cross marks each point where a section line meets a rail. A fine grain and blurred color fields lie behind the first section.

## Build the files

`python scripts/build_brand_assets.py --fonts <folder>` writes the files in `docs/brand/`. The docstring of the script names the two font files and the two Python packages that it needs. They are not engine dependencies.
