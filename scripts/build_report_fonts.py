"""Build the font subsets of the HTML report theme (src/kalkan/report/assets, docs/BRAND.md).

The reports embed Geist and Geist Mono (SIL OFL 1.1, no Reserved Font Name) as WOFF2 data URIs.
The subsets keep Basic Latin, Latin-1, Latin Extended-A (the Turkish letters) and a few symbols,
with the variable weight axis. The script is not part of the engine and has its own
dependencies:

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
OUT = ROOT / "src" / "kalkan" / "report" / "assets"
JOBS = (("Geist-wght.ttf", "Geist-subset.woff2"), ("GeistMono-wght.ttf", "GeistMono-subset.woff2"))
SYMBOLS = (
    0x00B7, 0x00D7, 0x2013, 0x2014, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2026, 0x20AC,
    0x2116, 0x2190, 0x2192, 0x2212, 0x2264, 0x2265,
)  # fmt: skip
UNICODES = [*range(0x20, 0x7F), *range(0xA0, 0x180), *SYMBOLS]


def build(source: Path, target: Path) -> int:
    options = subset.Options()
    options.flavor = "woff2"
    options.layout_features = ["kern", "liga", "calt", "tnum", "ss01"]
    options.name_IDs = ["*"]
    options.notdef_outline = True
    font = subset.load_font(str(source), options)
    subsetter = subset.Subsetter(options)
    subsetter.populate(unicodes=UNICODES)
    subsetter.subset(font)
    subset.save_font(font, str(target), options)
    return target.stat().st_size


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fonts", type=Path, required=True, help="folder with the variable TTFs")
    args = parser.parse_args()
    for source, target in JOBS:
        size = build(args.fonts / source, OUT / target)
        print(f"{target}: {size} bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
