"""Build the kalkan brand files in docs/brand/ (see docs/BRAND.md).

The SVG files carry the text as outlines of Geist and Geist Mono (SIL OFL 1.1), so a viewer
needs no font. The script is not part of the engine and has its own dependencies:

    python -m pip install fonttools uharfbuzz
    gh api "repos/google/fonts/contents/ofl/geist/Geist%5Bwght%5D.ttf" \
        -H "Accept: application/vnd.github.raw" > <fonts>/Geist-wght.ttf
    gh api "repos/google/fonts/contents/ofl/geistmono/GeistMono%5Bwght%5D.ttf" \
        -H "Accept: application/vnd.github.raw" > <fonts>/GeistMono-wght.ttf
    python scripts/build_brand_assets.py --fonts <fonts>
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path

import uharfbuzz as hb
from fontTools.pens.boundsPen import BoundsPen
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "brand"

THEMES = {
    "dark": {
        "bg": "#0A0A0A",
        "fg": "#F7F6F3",
        "muted": "#8F8D87",
        "accent": "#FF7A1A",
        "ink": "#FFFFFF",
        "line_op": "0.1",
        "cmd_op": "0.05",
        "glow_op": "0.3",
        "field": "#143A2F",
        "field_op": "0.85",
        "grain": "1",
        "grain_op": "0.07",
    },
    "light": {
        "bg": "#FAFAF8",
        "fg": "#0A0A0A",
        "muted": "#6C6A65",
        "accent": "#C2540A",
        "ink": "#0A0A0A",
        "line_op": "0.1",
        "cmd_op": "0.04",
        "glow_op": "0.16",
        "field": "#CDEEE0",
        "field_op": "0.9",
        "grain": "0",
        "grain_op": "0.035",
    },
}
TRACKING = -0.045  # letter spacing of the wordmark and the slogan, in em
STOP_GAP, STOP_WIDTH = 0.04, 0.27  # the shield-shaped full stop after the word, in em
STOP = "M0 0H6V2.7C6 4.7 4.6 6.1 3 7 1.4 6.1 0 4.7 0 2.7Z"  # 6 x 7 units, base on the baseline
SLOGAN = "Last stop before production."
DESCRIPTOR = "Security audit for source code, inside Claude Code."
COMMAND = "kalkan-audit ./shop --profile deep"
TOP_LABEL = "security audit · claude code"
BOTTOM_LABEL = "quoted findings · local scans · resumable"


def num(value: float) -> str:
    text = f"{value:.2f}".rstrip("0").rstrip(".")
    return "0" if text in ("", "-0") else text


class Face:
    """A static instance of a variable font: HarfBuzz shapes the text, fontTools draws it."""

    def __init__(self, path: Path, weight: int) -> None:
        buffer = io.BytesIO()
        instantiateVariableFont(TTFont(path), {"wght": weight}).save(buffer)
        data = buffer.getvalue()
        font = TTFont(io.BytesIO(data))
        self.upem = font["head"].unitsPerEm
        self.glyphs = font.getGlyphSet()
        self.order = font.getGlyphOrder()
        self.cmap = font.getBestCmap()
        self.hb_font = hb.Font(hb.Face(data))

    def shape(self, text: str) -> list:
        missing = sorted({ch for ch in text if ord(ch) not in self.cmap and not ch.isspace()})
        if missing:
            raise SystemExit(f"the font has no glyph for {missing!r}")
        buf = hb.Buffer()
        buf.add_str(text)
        buf.guess_segment_properties()
        hb.shape(self.hb_font, buf, {"kern": True, "liga": True})
        return [
            (self.order[info.codepoint], pos)
            for info, pos in zip(buf.glyph_infos, buf.glyph_positions, strict=True)
        ]

    def width(self, text: str, size: float, tracking: float = 0.0) -> float:
        runs = self.shape(text)
        advance = sum(pos.x_advance for _, pos in runs) * size / self.upem
        return advance + tracking * size * (len(runs) - 1)

    def bounds(self, text: str) -> tuple[float, float]:
        """Left edge and top of the ink of the first glyph, in em."""
        pen = BoundsPen(self.glyphs)
        self.glyphs[self.shape(text)[0][0]].draw(pen)
        return pen.bounds[0] / self.upem, pen.bounds[3] / self.upem

    def path(self, text: str, size: float, x: float, baseline: float, tracking: float = 0.0) -> str:
        scale = size / self.upem
        pen = SVGPathPen(self.glyphs, ntos=num)
        for name, pos in self.shape(text):
            offset = (x + pos.x_offset * scale, baseline - pos.y_offset * scale)
            self.glyphs[name].draw(TransformPen(pen, (scale, 0, 0, -scale, *offset)))
            x += pos.x_advance * scale + tracking * size
        return pen.getCommands()


def full_stop(x: float, baseline: float, size: float, fill: str) -> str:
    scale = STOP_WIDTH * size / 6
    move = f"translate({num(x)} {num(baseline - 7 * scale)}) scale({num(scale)})"
    return f'<path transform="{move}" fill="{fill}" d="{STOP}"/>'


def wordmark(face: Face, x: float, center_y: float, size: float, theme: dict) -> tuple[str, float]:
    """The logo: "kalkan" and its shield-shaped full stop, centred on center_y.
    Returns the SVG and the right edge."""
    baseline = center_y + face.bounds("k")[1] * size / 2
    word = face.path("kalkan", size, x, baseline, TRACKING)
    stop_x = x + face.width("kalkan", size, TRACKING) + STOP_GAP * size
    svg = f'<path fill="{theme["fg"]}" d="{word}"/>' + full_stop(
        stop_x, baseline, size, theme["accent"]
    )
    return svg, stop_x + STOP_WIDTH * size


def mark(face: Face, theme: dict) -> str:
    """The mark on a 32-unit grid: the k of the wordmark and the full stop, at most 24 units."""
    left, top = face.bounds("k")
    advance = face.width("k", 1)
    width = advance + STOP_GAP + STOP_WIDTH - left
    size = 24 / max(width, top)
    x = (32 - width * size) / 2 - left * size
    baseline = (32 + top * size) / 2
    letter = f'<path fill="{theme["fg"]}" d="{face.path("k", size, x, baseline)}"/>'
    return letter + full_stop(x + (advance + STOP_GAP) * size, baseline, size, theme["accent"])


def document(width: float, height: float, title: str, body: str) -> str:
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{num(width)}" height="{num(height)}" '
        f'viewBox="0 0 {num(width)} {num(height)}" role="img" aria-labelledby="title">'
        f'<title id="title">{title}</title>{body}</svg>\n'
    )


def build_mark(face: Face, theme: dict) -> str:
    return document(32, 32, "kalkan", mark(face, theme))


def build_icon(face: Face) -> str:
    theme = THEMES["dark"]
    tile = f'<rect width="32" height="32" rx="7" fill="{theme["bg"]}"/>'
    return document(
        32,
        32,
        "kalkan",
        f'{tile}<g transform="translate(4.8 4.8) scale(0.7)">{mark(face, theme)}</g>',
    )


def build_logo(face: Face, theme: dict) -> str:
    """The wordmark with 2 units of space around its ink."""
    size = 64
    left, top = face.bounds("k")
    height = top * size + 4
    body, right = wordmark(face, 2 - left * size, height / 2, size, theme)
    return document(right + 2, height, "kalkan", body)


def build_banner(faces: dict[str, Face], theme: dict) -> str:
    width, height, left, right = 1280, 400, 112, 1168
    t = theme
    if faces["600"].width(SLOGAN, 70, TRACKING) > right - left:
        raise SystemExit("the slogan is wider than the banner")
    defs = (
        "<defs>"
        f'<clipPath id="frame"><rect width="{width}" height="{height}" rx="16"/></clipPath>'
        '<filter id="blur" x="-50%" y="-50%" width="200%" height="200%">'
        '<feGaussianBlur stdDeviation="90"/></filter>'
        '<filter id="grain" x="0" y="0" width="100%" height="100%">'
        '<feTurbulence type="fractalNoise" baseFrequency="0.8" numOctaves="2" '
        'stitchTiles="stitch"/>'
        f'<feColorMatrix values="0 0 0 0 {t["grain"]} 0 0 0 0 {t["grain"]} 0 0 0 0 {t["grain"]} '
        '0 0 0 0.9 0"/></filter></defs>'
    )
    line = f'stroke="{t["ink"]}" stroke-opacity="{t["line_op"]}"'
    ground = (
        '<g clip-path="url(#frame)">'
        f'<rect width="{width}" height="{height}" fill="{t["bg"]}"/>'
        f'<circle cx="1120" cy="-30" r="300" fill="{t["accent"]}" fill-opacity="{t["glow_op"]}" '
        'filter="url(#blur)"/>'
        f'<circle cx="110" cy="440" r="260" fill="{t["field"]}" fill-opacity="{t["field_op"]}" '
        'filter="url(#blur)"/>'
        f'<rect width="{width}" height="{height}" filter="url(#grain)" opacity="{t["grain_op"]}"/>'
        f'<path d="M64 0V{height}M1216 0V{height}" {line}/>'
        "</g>"
        f'<rect x="0.5" y="0.5" width="{width - 1}" height="{height - 1}" rx="15.5" '
        f'fill="none" {line}/>'
    )
    logo, _ = wordmark(faces["600"], left, 66, 34, t)
    mono, mono500 = faces["mono"], faces["mono500"]
    top_label = mono.path(TOP_LABEL, 15, right - mono.width(TOP_LABEL, 15), 71.5)
    bottom_label = mono.path(BOTTOM_LABEL, 15, right - mono.width(BOTTOM_LABEL, 15), 329.5)
    text = (
        f'<path fill="{t["muted"]}" d="{top_label}"/>'
        f'<path fill="{t["fg"]}" d="{faces["600"].path(SLOGAN, 70, left - 3, 216, TRACKING)}"/>'
        f'<path fill="{t["muted"]}" d="{faces["400"].path(DESCRIPTOR, 24, left, 262)}"/>'
        f'<path fill="{t["muted"]}" d="{bottom_label}"/>'
    )
    pill_width = 40 + mono500.width(COMMAND, 19) + 22
    command = (
        f'<rect x="{left}" y="300" width="{num(pill_width)}" height="48" rx="10" fill="{t["ink"]}" '
        f'fill-opacity="{t["cmd_op"]}" {line}/>'
        f'<path d="M{left + 19} 317.5 {left + 25.5} 324 {left + 19} 330.5" fill="none" '
        f'stroke="{t["accent"]}" stroke-width="2.4" stroke-linecap="round" '
        'stroke-linejoin="round"/>'
        f'<path fill="{t["fg"]}" d="{mono500.path(COMMAND, 19, left + 40, 330.5)}"/>'
    )
    title = f"kalkan. {SLOGAN} {DESCRIPTOR}"
    return document(width, height, title, defs + ground + logo + text + command)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--fonts", type=Path, required=True, help="folder with the two font files")
    parser.add_argument("--out", type=Path, default=OUT)
    args = parser.parse_args()
    faces = {
        "400": Face(args.fonts / "Geist-wght.ttf", 400),
        "600": Face(args.fonts / "Geist-wght.ttf", 600),
        "mono": Face(args.fonts / "GeistMono-wght.ttf", 400),
        "mono500": Face(args.fonts / "GeistMono-wght.ttf", 500),
    }
    files = {
        "kalkan-mark-dark.svg": build_mark(faces["600"], THEMES["dark"]),
        "kalkan-mark-light.svg": build_mark(faces["600"], THEMES["light"]),
        "kalkan-icon.svg": build_icon(faces["600"]),
        "kalkan-logo-dark.svg": build_logo(faces["600"], THEMES["dark"]),
        "kalkan-logo-light.svg": build_logo(faces["600"], THEMES["light"]),
        "kalkan-banner-dark.svg": build_banner(faces, THEMES["dark"]),
        "kalkan-banner-light.svg": build_banner(faces, THEMES["light"]),
    }
    args.out.mkdir(parents=True, exist_ok=True)
    for name, text in files.items():
        (args.out / name).write_text(text, encoding="utf-8", newline="\n")
        print(f"{len(text.encode()):>7} B  {name}")


if __name__ == "__main__":
    main()
