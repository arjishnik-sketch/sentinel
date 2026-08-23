"""
Faithful PNG preview of the Sentinel deck.

Mirrors the exact inch/point coordinates used by build_deck.py and renders
with the same fonts (Consolas / Segoe UI) so the preview matches what
PowerPoint will show. Imports SLIDES straight from build_deck so slide
content cannot drift between the deck and its preview.

    ./.venv_docs/bin/python assets/preview_deck.py
Writes .sentinel_preview_all.png (a contact sheet of every slide) to the repo root.
"""

import os
from PIL import Image, ImageDraw, ImageFont

from build_deck import SLIDES, BRAND, ROOT

IN = 144            # px per inch  (1920 / 13.333)
PT = 2              # px per point (144 / 72)
W, H = 1920, 1080
FONTDIR = "/mnt/c/Windows/Fonts"

CYAN = (34, 211, 238)
MAGENTA = (232, 75, 255)
WHITE = (234, 242, 255)
BODY = (196, 210, 228)
DIM = (107, 122, 144)
GREEN = (45, 212, 143)
AMBER = (245, 179, 1)
RED = (255, 92, 110)

CONSOLA = "consola.ttf"
CONSOLAB = "consolab.ttf"
SEGOE = "segoeui.ttf"
SEGOEB = "segoeuib.ttf"
SEGUISYM = "seguisym.ttf"  # ✓/✗ live here, not in Segoe UI proper

_GLYPH = {"ok": ("»", GREEN, WHITE), "next": ("»", AMBER, WHITE),
          "cyan": ("»", CYAN, BODY), "warn": ("»", MAGENTA, BODY)}
_CELL = {"yes": ("✓", GREEN), "partial": ("~", AMBER), "no": ("✗", RED)}


def f(name, pt):
    return ImageFont.truetype(os.path.join(FONTDIR, name), int(pt * PT))


def _fit(im, maxw_in, maxh_in):
    ar = im.width / im.height
    w, h = maxw_in, maxw_in / ar
    if h > maxh_in:
        h, w = maxh_in, maxh_in * ar
    return w, h
# __REST__

def _bullets(d, bullets, left_in, top_in, size, gap_pt):
    x = int(left_in * IN)
    y = int(top_in * IN)
    fbb = f(SEGOEB, size)
    fb = f(SEGOE, size)
    for b in bullets:
        kind, text = ("cyan", b) if isinstance(b, str) else b
        glyph, gcol, tcol = _GLYPH[kind]
        gstr = glyph + "  "
        d.text((x, y), gstr, font=fbb, fill=gcol, anchor="la")
        gw = d.textlength(gstr, font=fbb)
        d.text((x + gw, y), text, font=fb, fill=tcol, anchor="la")
        y += int(size * PT * 1.32) + int(gap_pt * PT)


def _picture(im_base, d, name, box):
    left, top, maxw, maxh = box
    pic = Image.open(os.path.join(BRAND, name)).convert("RGBA")
    w, h = _fit(pic, maxw, maxh)
    pic = pic.resize((int(w * IN), int(h * IN)))
    x = left + (maxw - w) / 2
    y = top + (maxh - h) / 2
    im_base.alpha_composite(pic, (int(x * IN), int(y * IN)))
    return x, y, w, h


def _stats(d, stats, top):
    n = len(stats)
    gapw, total = 0.35, 12.0
    cw = (total - gapw * (n - 1)) / n
    for i, (val, lab) in enumerate(stats):
        x = 0.66 + i * (cw + gapw)
        x0, y0 = int(x * IN), int(top * IN)
        x1, y1 = int((x + cw) * IN), int((top + 1.25) * IN)
        d.rounded_rectangle([x0, y0, x1, y1], radius=12, outline=CYAN, width=2)
        cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
        d.text((cx, cy - int(0.16 * IN)), val, font=f(CONSOLAB, 32), fill=CYAN, anchor="mm")
        d.text((cx, cy + int(0.34 * IN)), lab.upper(), font=f(CONSOLA, 11), fill=DIM, anchor="mm")


def _compare(im_base, d, cols, rows, top):
    x_lab, x0, cw = 0.72, 7.15, 1.85
    for j, c in enumerate(cols):
        cx = int((x0 + j * cw + cw / 2) * IN)
        for k, line in enumerate(c.split("\n")):
            d.text((cx, int((top + 0.18 + k * 0.28) * IN)), line, font=f(CONSOLAB, 12),
                   fill=WHITE, anchor="ma")
    y = top + 0.78
    rh = 0.52
    for ri, (label, states) in enumerate(rows):
        if ri % 2 == 0:
            d.rectangle([int(0.6 * IN), int(y * IN), int(12.7 * IN), int((y + rh) * IN)],
                        fill=(16, 23, 36))
        d.text((int(x_lab * IN), int((y + rh / 2) * IN)), label, font=f(SEGOE, 14),
               fill=BODY, anchor="lm")
        for j, stt in enumerate(states):
            glyph, col = _CELL[stt]
            cx = int((x0 + j * cw + cw / 2) * IN)
            d.text((cx, int((y + rh / 2) * IN)), glyph, font=f(SEGUISYM, 18), fill=col, anchor="mm")
        y += rh
# __REST2__

def _header(im, d, s):
    mark = Image.open(os.path.join(BRAND, "sentinel_mark.png")).convert("RGBA")
    msz = int(0.82 * IN)
    im.alpha_composite(mark.resize((msz, msz)), (int(0.62 * IN), int(0.5 * IN)))
    bx0, by0 = int(11.15 * IN), int(0.5 * IN)
    bx1, by1 = int((11.15 + 1.7) * IN), int((0.5 + 0.42) * IN)
    d.rounded_rectangle([bx0, by0, bx1, by1], radius=10, outline=CYAN, width=2)
    d.text(((bx0 + bx1) // 2, (by0 + by1) // 2), "AI KAVACH", font=f(CONSOLAB, 12),
           fill=CYAN, anchor="mm")
    d.text((int(1.65 * IN), int(1.095 * IN)), s["title"], font=f(CONSOLAB, 31),
           fill=WHITE, anchor="lm")
    rule = Image.open(os.path.join(BRAND, "deck_rule.png")).convert("RGBA")
    rule = rule.resize((int(3.4 * IN), max(6, int(0.062 * IN))))
    im.alpha_composite(rule, (int(0.7 * IN), int(1.82 * IN)))
    d.text((int(0.72 * IN), int(2.02 * IN)), s["subtitle"], font=f(CONSOLA, 16),
           fill=CYAN, anchor="la")


def render_slide(idx, s):
    kind = s.get("kind", "content")
    bgname = {"title": "deck_bg_title.png", "divider": "deck_bg_divider.png"}.get(
        kind, "deck_bg.png")
    im = Image.open(os.path.join(BRAND, bgname)).convert("RGBA").resize((W, H))
    d = ImageDraw.Draw(im)

    if kind == "title":
        lock = Image.open(os.path.join(BRAND, "sentinel_logo_transparent.png")).convert("RGBA")
        lw = int(9.2 * IN)
        lh = int(lw * lock.height / lock.width)
        im.alpha_composite(lock.resize((lw, lh)), (int((13.333 - 9.2) / 2 * IN), int(1.55 * IN)))
        lh_in = 9.2 * lock.height / lock.width
        cx = W // 2
        d.text((cx, int((1.7 + lh_in) * IN)), s["subtitle"], font=f(CONSOLA, 18),
               fill=CYAN, anchor="ma")
        y = int((2.35 + lh_in) * IN)
        fb = f(SEGOE, 15)
        for b in s["bullets"]:
            text = b if isinstance(b, str) else b[1]
            d.text((cx, y), text, font=fb, fill=BODY, anchor="ma")
            y += int(15 * PT * 1.3) + int(7 * PT)
        d.text((cx, int(6.85 * IN)), "AI KAVACH CHALLENGE  ·  AUTONOMOUS CYBER-REASONING",
               font=f(CONSOLAB, 11), fill=DIM, anchor="ma")
        return im.convert("RGB")

    if kind == "divider":
        d.text((W // 2, int(3.5 * IN)), s["title"], font=f(CONSOLAB, 40), fill=WHITE,
               anchor="mm")
        rule = Image.open(os.path.join(BRAND, "deck_rule.png")).convert("RGBA")
        rule = rule.resize((int(3.4 * IN), max(6, int(0.062 * IN))))
        im.alpha_composite(rule, (int((13.333 - 3.4) / 2 * IN), int(4.35 * IN)))
        d.text((W // 2, int(4.9 * IN)), s["subtitle"], font=f(CONSOLA, 18), fill=CYAN,
               anchor="mm")
        return im.convert("RGB")

    _header(im, d, s)
    _render_body(im, d, s)
    d.text((int(0.62 * IN), int(6.98 * IN)),
           "SENTINEL   ·   find → reason → prove → patch → prove",
           font=f(CONSOLAB, 10), fill=DIM, anchor="la")
    d.text((int(12.8 * IN), int(6.98 * IN)), f"{idx:02d} / {len(SLIDES):02d}",
           font=f(CONSOLA, 10), fill=DIM, anchor="ra")
    return im.convert("RGB")
# __REST3__

def _render_body(im, d, s):
    image = s.get("image")
    layout = s.get("layout", "right")
    if "cols" in s:
        _compare(im, d, s["cols"], s["rows"], top=2.62)
    elif "stats" in s:
        _stats(d, s["stats"], top=2.62)
        if s.get("bullets"):
            _bullets(d, s["bullets"], 0.78, 4.2, 17, 10)
    elif image and layout == "full":
        _, iy, _, ih = _picture(im, d, image, (1.0, 2.55, 11.3, 4.05))
        cap = s.get("caption")
        if cap:
            d.text((W // 2, int((iy + ih + 0.1) * IN)), cap, font=f(CONSOLA, 12),
                   fill=DIM, anchor="ma")
    elif image:
        _picture(im, d, image, (7.0, 2.55, 5.85, 4.15))
        if s.get("bullets"):
            _bullets(d, s["bullets"], 0.78, 2.72, 16, 12)
    else:
        _bullets(d, s["bullets"], 0.78, 2.95, 18, 15)


def main():
    tiles = [render_slide(i, s) for i, s in enumerate(SLIDES, start=1)]
    tw = 1000
    th = int(tw * H / W)
    gap = 16
    sheet = Image.new("RGB", (tw, th * len(tiles) + gap * (len(tiles) - 1)), (3, 5, 9))
    for i, t in enumerate(tiles):
        sheet.paste(t.resize((tw, th)), (0, i * (th + gap)))
    out = os.path.join(ROOT, ".sentinel_preview_all.png")
    sheet.save(out, quality=92)
    print("wrote", out, sheet.size, f"({len(tiles)} slides)")


if __name__ == "__main__":
    main()



