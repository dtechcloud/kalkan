# SPDX-License-Identifier: MIT
"""The report theme "Gece" (docs/BRAND.md): the look of the kalkan site, for every HTML report.

``REPORT.html`` (:mod:`kalkan.report.render_html`) and ``EXECUTIVE.html``
(:mod:`kalkan.report.render_exec`) share this module: the fonts, the design tokens, the print
tokens and the shared components (links, code, the theme toggle, the severity badge, the status
dot). Each page adds its own layout.

- **Dark first.** The page opens dark, as the site does. ``prefers-color-scheme: light`` or the
  theme toggle (``data-theme="light"``) gives the light tokens of the site. Print uses the light
  tokens on white.
- **Self-contained.** Geist and Geist Mono (SIL OFL 1.1, ``assets/OFL.txt``) are embedded as
  WOFF2 data URIs: Latin, Latin-1, Latin Extended-A (the Turkish letters) and a few symbols
  (``scripts/build_report_fonts.py``). The logo is an embedded SVG data URI. The page makes no
  network request. Without the fonts the system font stacks take over.
- **Severity.** A small shield in the severity color stands before the severity word. The color
  never stands alone.
"""

from __future__ import annotations

import base64
from importlib import resources
from typing import Final

__all__ = ["COMPONENTS", "FONT_FACES", "PRINT_TOKENS", "THEME_NAME", "TOKENS", "asset_bytes"]

THEME_NAME: Final = "gece"


def asset_bytes(name: str) -> bytes:
    """Return the bytes of one file in ``kalkan/report/assets``."""
    return resources.files("kalkan.report").joinpath("assets", name).read_bytes()


def _data_uri(mime: str, name: str) -> str:
    return f"data:{mime};base64,{base64.b64encode(asset_bytes(name)).decode('ascii')}"


FONT_FACES: Final = "".join(
    f'@font-face {{ font-family: "{family}"; font-style: normal; font-weight: 100 900; '
    f'font-display: swap; src: url({_data_uri("font/woff2", file)}) format("woff2"); }}\n'
    for family, file in (("Geist", "Geist-subset.woff2"), ("Geist Mono", "GeistMono-subset.woff2"))
)

_COMMON: Final = {
    "sans": '"Geist", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
    "mono": '"Geist Mono", ui-monospace, "Cascadia Mono", SFMono-Regular, Menlo, Consolas, '
    "monospace",
    "logo-dark": f"url({_data_uri('image/svg+xml', 'kalkan-logo-dark.svg')})",
    "logo-light": f"url({_data_uri('image/svg+xml', 'kalkan-logo-light.svg')})",
    "r": "14px",
}
#: The site's dark tokens (site/assets/site.css), with the report's severity colors.
DARK: Final = {
    "canvas": "#0a0a0a", "raise": "#121211", "sunk": "#070707", "fg": "#f7f6f3",
    "body": "#c9c7c2", "muted": "#8f8d87", "faint": "#55534f",
    "line": "rgb(255 255 255 / 0.1)", "line-strong": "rgb(255 255 255 / 0.2)",
    "fill": "rgb(255 255 255 / 0.04)", "fill-strong": "rgb(255 255 255 / 0.09)",
    "accent": "#ff7a1a", "accent-soft": "rgb(255 122 26 / 0.2)",
    "pass": "#3fb950", "warn": "#e3b341", "fail": "#f85149",
    "sev-c": "#ff6b5e", "sev-h": "#ff8a4c", "sev-m": "#e3b341", "sev-l": "#7aa7ff",
    "sev-i": "#8f8d87", "field-a": "#4a2a12", "field-b": "#143a2f", "logo": "var(--logo-dark)",
}  # fmt: skip
#: The site's light tokens.
LIGHT: Final = {
    "canvas": "#fafaf8", "raise": "#ffffff", "sunk": "#f3f2ef", "fg": "#0a0a0a",
    "body": "#3b3a37", "muted": "#6c6a65", "faint": "#b5b3ad",
    "line": "rgb(10 10 10 / 0.1)", "line-strong": "rgb(10 10 10 / 0.2)",
    "fill": "rgb(10 10 10 / 0.03)", "fill-strong": "rgb(10 10 10 / 0.07)",
    "accent": "#c2540a", "accent-soft": "rgb(194 84 10 / 0.14)",
    "pass": "#1a7f37", "warn": "#9a6700", "fail": "#cf222e",
    "sev-c": "#b42318", "sev-h": "#c4400c", "sev-m": "#9a6700", "sev-l": "#2f5fb3",
    "sev-i": "#6c6a65", "field-a": "#ffe0c7", "field-b": "#cdeee0", "logo": "var(--logo-light)",
}  # fmt: skip


def _decl(tokens: dict[str, str], scheme: str) -> str:
    body = " ".join(f"--{key}: {value};" for key, value in tokens.items())
    return f"{body} color-scheme: {scheme};"


TOKENS: Final = (
    f":root {{ {_decl(_COMMON | DARK, 'dark')} }}\n"
    "@media (prefers-color-scheme: light) {\n"
    f'  :root:not([data-theme="dark"]) {{ {_decl(LIGHT, "light")} }}\n'
    "}\n"
    f':root[data-theme="light"] {{ {_decl(LIGHT, "light")} }}\n'
    f':root[data-theme="dark"] {{ {_decl(DARK, "dark")} }}\n'
)

#: The print tokens, inside ``@media print``: light on white. The selector outranks
#: ``:root[data-theme]``.
PRINT_TOKENS: Final = (
    "  :root:not([data-print]):not([data-x]) { "
    + _decl(LIGHT | {"canvas": "#ffffff", "raise": "#ffffff", "sunk": "#f6f5f2"}, "light")
    + " }\n"
)

#: Shared elements and components. Each page adds its layout after this block.
COMPONENTS: Final = """* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0; background: var(--canvas); color: var(--body); font-family: var(--sans);
  line-height: 1.55; -webkit-font-smoothing: antialiased;
}
::selection { background: var(--accent-soft); }
a {
  color: var(--fg); text-decoration: underline; text-decoration-color: var(--line-strong);
  text-decoration-thickness: 1px; text-underline-offset: 3px;
}
a:hover { text-decoration-color: var(--accent); }
a:focus-visible, button:focus-visible { outline: 2px solid var(--fg); outline-offset: 2px; }
code { font-family: var(--mono); font-size: 0.86em; overflow-wrap: anywhere; color: var(--fg); }
b, strong { color: var(--fg); font-weight: 600; }
.logo-head::before {
  content: ""; display: block; width: 7.2rem; height: 1.7rem; margin-bottom: 1.8rem;
  background: var(--logo) no-repeat left center / contain;
}
.field {
  background:
    radial-gradient(42rem 26rem at 105% -20%, var(--field-a), transparent 70%),
    radial-gradient(36rem 28rem at -10% 40%, var(--field-b), transparent 70%),
    var(--canvas);
}
.theme-toggle {
  position: absolute; top: 0; right: 0; font: 500 0.7rem/1 var(--mono); letter-spacing: 0.08em;
  text-transform: uppercase; color: var(--muted); background: var(--fill);
  border: 1px solid var(--line-strong); border-radius: 999px; padding: 0.5rem 0.85rem;
  cursor: pointer;
}
.theme-toggle:hover { color: var(--fg); }
.sev {
  --sev: var(--sev-i); display: inline-flex; align-items: center; gap: 0.4rem;
  white-space: nowrap; font-size: 0.78rem; font-weight: 500; line-height: 1.5; color: var(--fg);
  padding: 0.1rem 0.6rem 0.1rem 0.5rem; border-radius: 999px; background: var(--fill);
  background: color-mix(in oklab, var(--sev) 14%, transparent);
  border: 1px solid var(--line-strong);
  border-color: color-mix(in oklab, var(--sev) 38%, transparent);
}
.sev::before {
  content: ""; width: 0.6rem; height: 0.7rem; flex: none; background: var(--sev);
  clip-path: polygon(0 0, 100% 0, 100% 52%, 50% 100%, 0 52%);
}
.sev.sev-critical { --sev: var(--sev-c); } .sev.sev-high { --sev: var(--sev-h); }
.sev.sev-medium { --sev: var(--sev-m); } .sev.sev-low { --sev: var(--sev-l); }
.sev.sev-info, .sev.sev-none { --sev: var(--sev-i); }
.st { display: inline-flex; align-items: center; gap: 0.45rem; white-space: nowrap; }
.st::before { content: ""; width: 7px; height: 7px; border-radius: 50%; flex: none; }
.st-good::before { background: var(--pass); } .st-warn::before { background: var(--warn); }
.st-crit::before { background: var(--fail); }
.st-neutral::before { background: var(--line-strong); }
.nt { color: var(--muted); font-style: italic; font-size: 0.9em; }
"""
