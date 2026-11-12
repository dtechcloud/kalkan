"""Build the font subsets of the HTML reports and of the site (docs/BRAND.md).

The reports embed Geist and Geist Mono (SIL OFL 1.1, no Reserved Font Name) as WOFF2 data URIs
(src/kalkan/report/assets). The site serves the same fonts from its own origin
(site/assets/fonts), so a visit makes no request to a font service. The subsets keep Basic
Latin, Latin-1, Latin Extended-A (the Turkish letters) and a few symbols, with the variable
weight axis. The site subsets also keep the symbols that the site uses. The script is not
part of the engine and has its own dependencies:

    python -m pip install fonttools brotli
    gh api "repos/google/fonts/contents/ofl/geist/Geist%5Bwght%5D.ttf" \\
        -H "Accept: application/vnd.github.raw" > <fonts>/Geist-wght.ttf
    gh api "repos/google/fonts/contents/ofl/geistmono/GeistMono%5Bwght%5D.ttf" \\
        -H "Accept: application/vnd.github.raw" > <fonts>/GeistMono-wght.ttf
    python scripts/build_report_fonts.py --fonts <fonts>

The license text is src/kalkan/report/assets/OFL.txt (https://github.com/vercel/geist-font).
"""

from __future__ import annotations

import argparse
from pathlib import Path

from fontTools import subset

ROOT = Path(__file__).resolve().parents[1]
REPORT = ROOT / "src" / "kalkan" / "report" / "assets"
SITE = ROOT / "site" / "assets" / "fonts"
FILES = (("Geist-wght.ttf", "Geist-subset.woff2"), ("GeistMono-wght.ttf", "GeistMono-subset.woff2"))
SYMBOLS = (
    0x00B7, 0x00D7, 0x2013, 0x2014, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2026, 0x20AC,
    0x2116, 0x2190, 0x2192, 0x2212, 0x2264, 0x2265,
)  # fmt: skip
#: The site also shows these: ↳ ▍ ○ ● (the other symbols of the site are not in Geist).
SITE_SYMBOLS = (0x21B3, 0x258D, 0x25CB, 0x25CF)
UNICODES = [*range(0x20, 0x7F), *range(0xA0, 0x180), *SYMBOLS]
JOBS = ((REPORT, UNICODES), (SITE, [*UNICODES, *SITE_SYMBOLS]))


def build(source: Path, target: Path, unicodes: list[int]) -> int:
    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = ["kern", "liga", "calt", "tnum", "ss01"]
    options.name_IDs = ["*"]
    options.notdef_outline = True
    font = subset.load_font(str(source), options)
    subsetter = subset.Subsetter(options)
    subsetter.populate(unicodes=unicodes)
    subsetter.subset(font)
    subset.save_font(font, str(target), options)
    return target.stat().st_size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fonts", type=Path, required=True, help="folder with the variable TTFs")
    args = parser.parse_args()
    for folder, unicodes in JOBS:
        folder.mkdir(parents=True, exist_ok=True)
        for source, target in FILES:
            size = build(args.fonts / source, folder / target, unicodes)
            print(f"{(folder / target).relative_to(ROOT).as_posix()}: {size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
