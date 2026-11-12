# scripts

- `vendor_third_party.py`: copy pinned upstream files into `third_party/` and verify them.
- `build_opengrep_packs.py`: build the Opengrep rule packs `rules/opengrep-packs` from the vendored copies and `curation.json`; `--check` compares with the disk (ADR-0005 K.8).
- `install.ps1`, `install.sh`: one-command install or update of the Claude Code plugin on a new machine (checks, marketplace, plugin, setup, and a `--dry-run` option). README.md, "Quick start", shows the `gh` one-liner.
- `bootstrap.ps1`, `bootstrap.sh`: install the pinned tools (phase 2).
- `run-unattended.ps1`, `run-unattended.sh`: headless resume loop (phase 6).
- `platform_check.sh`, `platform_report.py`: check that every tool works on a macOS or Linux machine (bootstrap, doctor, the tool tests, the vulnapp benchmark) and, with `--pr`, open a pull request with the result. `benchmarks/platforms/README.md` describes it.
- `sync_host_files.py`: generate the Codex files and the plugin skill and agents from the Claude Code files.
- `build_plugin.py`: build the plugin manifests and the bundled engine wheel (`plugins/kalkan/`, docs/PLUGIN.md).
- `gen_task_schemas.py`, `port_deepsec_matchers.py`: agent result schemas, deepsec matcher port.
- `build_brand_assets.py`: build the logo, icon and README banner files in `docs/brand/` (docs/BRAND.md). It needs `fonttools`, `uharfbuzz` and the Geist font files. These are not engine dependencies.
