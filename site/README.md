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
| `404.html` | Page not found (the links start with `/`, because it answers any path) |
| `assets/` | `site.css`, `site.js`, `analytics.js`, `kalkan-icon.svg` |
| `staticwebapp.config.json` | Azure Static Web Apps: security headers (CSP, HSTS), cache times, the 404 page |

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

## Hosting and deploy

Azure Static Web Apps (Standard) serves the site. `.github/workflows/site.yml` deploys it:

| Branch | Environment | Address |
|---|---|---|
| `stable` | production | kalkan.dtechcloud.com (the default host until the domain is set) |
| `main` | staging | the staging host of the same Static Web App |

The workflow signs in to Azure with OpenID Connect (OIDC): a user-assigned managed identity
with a federated credential for each GitHub environment. GitHub stores no Azure secret. The
identity has the Contributor role on the Static Web App only. The workflow reads the deploy
token at run time and masks it in the log.

Visit counts: `assets/analytics.js` loads the Application Insights JavaScript SDK (pinned
version, SRI hash) without cookies or browser storage. Only the production deploy puts the
connection string in the file. A local copy, a fork and the staging site send nothing.
