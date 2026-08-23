"""
Render captured Sentinel CLI ANSI (assets/brand/cli/*.ansi) to premium
"terminal window" PNGs for the pitch deck — assets/brand/shot_<name>.png.

Run under the docs venv (Pillow):
    ./.venv_docs/bin/python assets/render_shots.py

It parses the real ANSI SGR the engine emitted (standard / bright / 256 / truecolor
foreground + bold), maps the CLI's fixed palette onto the deck's neon RGB, and
paints Consolas monospace onto an ink-gradient canvas with subtle window chrome.
Nothing is re-authored: the glyphs and verdicts are exactly what the engine printed.
"""

from __future__ import annotations

import os
import re

from PIL import Image, ImageDraw, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
CLI_DIR = os.path.join(HERE, "brand", "cli")
OUT_DIR = os.path.join(HERE, "brand")

# ---- deck palette (mirrors assets/build_deck.py) ----
INK_TOP = (11, 16, 26)
INK_BOT = (6, 9, 15)
GRID = (18, 27, 42)
CYAN = (34, 211, 238)
MAGENTA = (232, 75, 255)
GREEN = (45, 212, 143)
AMBER = (245, 179, 1)
RED = (255, 92, 110)
WHITE = (234, 242, 255)
SOFT = (206, 218, 234)
BODY = (196, 210, 228)
DIM = (107, 122, 144)

FONT_DIR = "/mnt/c/Windows/Fonts"
FS = 20  # px; slides scale it down — capture crisp

# 8/16-colour SGR → neon
_BASE = {
    30: (60, 72, 92), 90: (74, 88, 108),
    31: RED, 91: RED,
    32: GREEN, 92: GREEN,
    33: AMBER, 93: AMBER,
    34: CYAN, 94: CYAN,
    35: MAGENTA, 95: MAGENTA,
    36: CYAN, 96: CYAN,
    37: SOFT, 97: WHITE,
}

_SGR = re.compile(r"\x1b\[([0-9;]*)m")
_FONT_CACHE: dict = {}
_NOTDEF_CACHE: dict = {}


def _xterm256(n: int) -> tuple[int, int, int]:
    if n < 16:
        return _BASE.get(30 + (n & 7) + (60 if n >= 8 else 0), BODY)
    if n < 232:
        n -= 16
        r, g, b = n // 36, (n // 6) % 6, n % 6
        conv = lambda v: 55 + v * 40 if v else 0
        return (conv(r), conv(g), conv(b))
    v = 8 + (n - 232) * 10
    return (v, v, v)


def _map256(n: int) -> tuple[int, int, int]:
    rgb = _xterm256(n)
    if max(rgb) - min(rgb) < 24:  # a grey → the deck's dim label ink
        return DIM
    return rgb


def _parse_line(line: str) -> list[tuple[str, tuple[int, int, int], bool]]:
    """Return per-character (glyph, rgb, bold), applying SGR state left→right."""
    cells: list[tuple[str, tuple[int, int, int], bool]] = []
    fg, bold = BODY, False
    pos = 0
    for m in _SGR.finditer(line):
        for ch in line[pos:m.start()]:
            cells.append((ch, fg, bold))
        pos = m.end()
        params = [int(p) if p else 0 for p in m.group(1).split(";")] or [0]
        i = 0
        while i < len(params):
            p = params[i]
            if p == 0:
                fg, bold = BODY, False
            elif p == 1:
                bold = True
            elif p == 22:
                bold = False
            elif p == 39:
                fg = BODY
            elif p == 38 and i + 1 < len(params) and params[i + 1] == 5:
                fg = _map256(params[i + 2]); i += 2
            elif p == 38 and i + 1 < len(params) and params[i + 1] == 2:
                fg = (params[i + 2], params[i + 3], params[i + 4]); i += 4
            elif p == 48 and i + 1 < len(params) and params[i + 1] == 5:
                i += 2  # background — ignored on the ink canvas
            elif p == 48 and i + 1 < len(params) and params[i + 1] == 2:
                i += 4
            elif p in _BASE:
                fg = _BASE[p]
            i += 1
    for ch in line[pos:]:
        cells.append((ch, fg, bold))
    return cells


def _font(bold: bool, size: int) -> ImageFont.FreeTypeFont:
    key = (bold, size)
    f = _FONT_CACHE.get(key)
    if f is None:
        name = "consolab.ttf" if bold else "consola.ttf"
        f = ImageFont.truetype(os.path.join(FONT_DIR, name), size)
        _FONT_CACHE[key] = f
    return f


def _fallback(size: int) -> ImageFont.FreeTypeFont:
    f = _FONT_CACHE.get(("sym", size))
    if f is None:
        f = ImageFont.truetype(os.path.join(FONT_DIR, "seguisym.ttf"), size)
        _FONT_CACHE[("sym", size)] = f
    return f


def _render_bytes(font: ImageFont.FreeTypeFont, ch: str, size: int) -> bytes:
    im = Image.new("L", (size * 2, size * 2), 0)
    ImageDraw.Draw(im).text((0, 0), ch, font=font, fill=255)
    return im.tobytes()


def _notdef(font: ImageFont.FreeTypeFont, size: int) -> bytes:
    key = (id(font), size)
    b = _NOTDEF_CACHE.get(key)
    if b is None:
        b = _render_bytes(font, "￿", size)  # missing → .notdef box
        _NOTDEF_CACHE[key] = b
    return b


def _has(font: ImageFont.FreeTypeFont, ch: str, size: int) -> bool:
    try:
        return _render_bytes(font, ch, size) != _notdef(font, size)
    except Exception:
        return True


def _glyph_font(ch: str, bold: bool, size: int) -> ImageFont.FreeTypeFont:
    """Consolas if it covers the glyph; else Segoe UI Symbol (for ✔ ✗ …)."""
    base = _font(bold, size)
    if _has(base, ch, size):
        return base
    fb = _fallback(size)
    return fb if _has(fb, ch, size) else base


def _canvas(w: int, h: int) -> Image.Image:
    """Ink gradient + faint grid + soft corner glows — matches the deck bg."""
    base = Image.new("RGB", (1, h))
    px = base.load()
    for y in range(h):
        t = y / max(1, h - 1)
        px[0, y] = tuple(int(INK_TOP[i] + (INK_BOT[i] - INK_TOP[i]) * t)
                         for i in range(3))
    base = base.resize((w, h)).convert("RGBA")
    grid = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grid)
    for x in range(0, w, 54):
        gd.line([(x, 0), (x, h)], fill=GRID + (255,))
    for y in range(0, h, 54):
        gd.line([(0, y), (w, y)], fill=GRID + (255,))
    base = Image.alpha_composite(base, grid)
    for cx, cy, col, a in ((60, 60, CYAN, 40), (w - 40, h - 20, MAGENTA, 34)):
        glow = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        r = 360
        ImageDraw.Draw(glow).ellipse([cx - r, cy - r, cx + r, cy + r],
                                     fill=col + (a,))
        base = Image.alpha_composite(base, glow.filter(
            ImageFilter.GaussianBlur(r * 0.5)))
    return base


# geometry
PAD = 34          # outer margin around the window
BODYPAD = 26      # inner text inset
HDR_DOTS = ((RED, "close"), (AMBER, "min"), (GREEN, "max"))


def render_shot(name: str, ansi_path: str) -> str:
    with open(ansi_path, encoding="utf-8") as fh:
        raw = fh.read().replace("\r\n", "\n").rstrip("\n")
    lines = [ln for ln in raw.split("\n")]
    # drop leading/trailing blank lines
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    parsed = [_parse_line(ln) for ln in lines]
    cols = max((len(c) for c in parsed), default=1)

    reg = _font(False, FS)
    cell_w = round(reg.getlength("M"))
    ascent, descent = reg.getmetrics()
    cell_h = ascent + descent + 2

    text_w = cols * cell_w
    text_h = len(parsed) * cell_h
    hdr_h = cell_h + 20
    win_w = text_w + 2 * BODYPAD
    win_h = hdr_h + text_h + 2 * BODYPAD
    W = win_w + 2 * PAD
    Hh = win_h + 2 * PAD

    img = _canvas(W, Hh)
    d = ImageDraw.Draw(img)

    # window body
    x0, y0, x1, y1 = PAD, PAD, PAD + win_w, PAD + win_h
    d.rounded_rectangle([x0, y0, x1, y1], radius=16, fill=(9, 13, 21, 235),
                        outline=(34, 211, 238, 90), width=2)
    # header bar
    d.rounded_rectangle([x0, y0, x1, y0 + hdr_h], radius=16,
                        fill=(14, 20, 32, 255))
    d.rectangle([x0, y0 + hdr_h - 16, x1, y0 + hdr_h], fill=(14, 20, 32, 255))
    d.line([x0, y0 + hdr_h, x1, y0 + hdr_h], fill=(34, 211, 238, 70), width=1)
    for i, (col, _lab) in enumerate(HDR_DOTS):
        cx = x0 + 22 + i * 22
        cy = y0 + hdr_h // 2
        d.ellipse([cx - 6, cy - 6, cx + 6, cy + 6], fill=col + (255,))
    tfont = _font(True, FS - 4)
    title = f"sentinel  —  {name}"
    d.text((x0 + 22 + 3 * 22 + 18, y0 + hdr_h // 2 - (FS - 4) // 2 - 2),
           title, font=tfont, fill=DIM)

    # body glyphs, cell-aligned so box-drawing connects
    bx = x0 + BODYPAD
    by = y0 + hdr_h + BODYPAD
    for r, cells in enumerate(parsed):
        y = by + r * cell_h
        for c, (ch, rgb, bold) in enumerate(cells):
            if ch == " ":
                continue
            d.text((bx + c * cell_w, y), ch, font=_glyph_font(ch, bold, FS),
                   fill=rgb)

    out = os.path.join(OUT_DIR, f"shot_{name}.png")
    img.convert("RGB").save(out, quality=95)
    return out


def main() -> None:
    if not os.path.isdir(CLI_DIR):
        raise SystemExit(f"no captures at {CLI_DIR}; run capture_cli.py first")
    names = sorted(f[:-5] for f in os.listdir(CLI_DIR) if f.endswith(".ansi"))
    if not names:
        raise SystemExit("no .ansi captures found")
    for name in names:
        out = render_shot(name, os.path.join(CLI_DIR, f"{name}.ansi"))
        print("wrote", os.path.relpath(out, ROOT))
    print(f"\nrendered {len(names)} shots")


if __name__ == "__main__":
    main()
