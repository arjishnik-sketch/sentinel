"""
Faithful PNG preview of the Sentinel deck.

Mirrors the exact inch/point coordinates used by build_deck.py and renders
with the same fonts (Consolas / Segoe UI) so the preview matches what
PowerPoint will show. Imports SLIDES straight from build_deck so slide
content cannot drift between the deck and its preview.

    python assets/preview_deck.py
Writes .sentinel_preview_all.png (a 5-slide contact sheet) to the repo root.
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


def f(name, pt):
    return ImageFont.truetype(os.path.join(FONTDIR, name), int(pt * PT))


CONSOLA = "consola.ttf"
CONSOLAB = "consolab.ttf"
SEGOE = "segoeui.ttf"
SEGOEB = "segoeuib.ttf"


def render_slide(idx, s):
    is_title = idx == 1
    bg = os.path.join(BRAND, "deck_bg_title.png" if is_title else "deck_bg.png")
    im = Image.open(bg).convert("RGBA").resize((W, H))
    d = ImageDraw.Draw(im)

    if is_title:
        lock = Image.open(os.path.join(BRAND, "sentinel_logo_transparent.png")).convert("RGBA")
        lw = int(9.2 * IN)
        lh = int(lw * lock.height / lock.width)
        lock = lock.resize((lw, lh))
        im.alpha_composite(lock, (int((13.333 - 9.2) / 2 * IN), int(1.55 * IN)))
        lh_inches = 9.2 * 520 / 1903
        cx = W // 2
        d.text((cx, int((1.7 + lh_inches) * IN)), s["subtitle"], font=f(CONSOLA, 19),
               fill=CYAN, anchor="ma")
        y = int((2.35 + lh_inches) * IN)
        fb = f(SEGOE, 15)
        for b in s["bullets"]:
            text = b if isinstance(b, str) else b[1]
            d.text((cx, y), text, font=fb, fill=BODY, anchor="ma")
            y += int(15 * PT * 1.3) + int(7 * PT)
        d.text((cx, int(6.85 * IN)), "AI KAVACH CHALLENGE  ·  AUTONOMOUS CYBER-REASONING",
               font=f(CONSOLAB, 11), fill=DIM, anchor="ma")
    else:
        mark = Image.open(os.path.join(BRAND, "sentinel_mark.png")).convert("RGBA")
        msz = int(0.82 * IN)
        mark = mark.resize((msz, msz))
        im.alpha_composite(mark, (int(0.62 * IN), int(0.5 * IN)))
        # badge
        bx0, by0 = int(11.15 * IN), int(0.5 * IN)
        bx1, by1 = int((11.15 + 1.7) * IN), int((0.5 + 0.42) * IN)
        d.rounded_rectangle([bx0, by0, bx1, by1], radius=10, outline=CYAN, width=2)
        d.text(((bx0 + bx1) // 2, (by0 + by1) // 2), "AI KAVACH", font=f(CONSOLAB, 12),
               fill=CYAN, anchor="mm")
        # title (middle-anchored in its box)
        d.text((int(1.65 * IN), int(1.095 * IN)), s["title"], font=f(CONSOLAB, 33),
               fill=WHITE, anchor="lm")
        # rule
        rule = Image.open(os.path.join(BRAND, "deck_rule.png")).convert("RGBA")
        rule = rule.resize((int(3.4 * IN), max(6, int(0.062 * IN))))
        im.alpha_composite(rule, (int(0.7 * IN), int(1.82 * IN)))
        # subtitle
        d.text((int(0.72 * IN), int(2.02 * IN)), s["subtitle"], font=f(CONSOLA, 17),
               fill=CYAN, anchor="la")
        # bullets
        y = int(2.95 * IN)
        fbb = f(SEGOEB, 19)
        fb = f(SEGOE, 19)
        x = int(0.78 * IN)
        for b in s["bullets"]:
            kind, text = ("cyan", b) if isinstance(b, str) else b
            glyph, gcol, tcol = {
                "ok": ("»", GREEN, WHITE),
                "next": ("»", AMBER, WHITE),
                "cyan": ("»", CYAN, BODY),
            }[kind]
            gstr = glyph + "  "
            d.text((x, y), gstr, font=fbb, fill=gcol, anchor="la")
            gw = d.textlength(gstr, font=fbb)
            d.text((x + gw, y), text, font=fb, fill=tcol, anchor="la")
            y += int(19 * PT * 1.32) + int(15 * PT)
        # footer
        d.text((int(0.62 * IN), int(6.98 * IN)), "SENTINEL   ·   find → reason → prove",
               font=f(CONSOLAB, 10), fill=DIM, anchor="la")
        d.text((int(12.8 * IN), int(6.98 * IN)), f"{idx:02d} / 05", font=f(CONSOLA, 10),
               fill=DIM, anchor="ra")

    return im.convert("RGB")


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
    print("wrote", out, sheet.size)


if __name__ == "__main__":
    main()
