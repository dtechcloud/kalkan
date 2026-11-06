# kalkan website

The product website. Plain, hand-written HTML with no build step: open `index.html` in a
browser, or serve the folder with any static file server.

| File | Page |
|---|---|
| `index.html` | Home |
| `how-it-works.html` | How it works |
| `tools.html` | Tools |
| `usage.html` | Usage |
| `docs.html` | Docs, getting started: requirements, installation, first audit, profiles, commands |
| `docs-audit.html` | Docs, audit: how kalkan works, tools, AI verification, PoC sandbox, SCA, reports, CI/CD |
| `docs-machine.html` | Docs, on your machine: what kalkan installs and where, disk usage, privacy, network, security model |
| `docs-maintenance.html` | Docs, maintenance: updating, troubleshooting, uninstall, full cleanup |
| `security.html` | Security |
| `compare.html` | Compare |
| `faq.html` | FAQ |
| `assets/` | `site.css`, `site.js`, `kalkan-icon.svg` |

The site offers no paid service. The only contact is the "Contact us" / "İletişim" button at the top right: it shows `kalkan@dtechcloud.com` with a copy button (on phones it is the last item of the menu). The footer shows the address too.

Every page carries English and Turkish in `<span class="en">` and `<span class="tr">` pairs. English is the default; `#tr` in the address or the TR button shows Turkish.
`assets/site.js` switches the language and the theme and keeps the choice across pages. The
look follows `docs/BRAND.md` (Geist and Geist Mono from Google Fonts, accent `#FF7A1A`,
dark first).

The four docs pages share one nav: the side table of contents (wide screens) and the
contents list (phones) show the same groups and numbers on each page. A link to a section of
the same page starts with `#`, so that `site.js` can mark the section that you read. When you
add, move or rename a docs section, change the nav and the section numbers on all four pages.

The only external requests are the Google Fonts stylesheet and the font files. Everything
else is in this folder.

