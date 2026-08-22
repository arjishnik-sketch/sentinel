"""
Sentinel brand asset generator.

Renders a neon "cyber" logo — a hexagonal shield enclosing an "S"
monogram with a scan-line and targeting reticle — plus a horizontal
wordmark lockup. Everything is drawn at high supersampling and
downscaled with LANCZOS for crisp, anti-aliased edges.

Run with a Python that has Pillow installed:
    python assets/build_brand.py
Outputs land in assets/brand/.
"""

import math
import os

from PIL import Image, ImageDraw, ImageFont, ImageFilter

# ---- palette (matches the CLI: bright cyan + bright magenta on ink) ----
CYAN = (34, 211, 238)      # #22D3EE
MAGENTA = (232, 75, 255)   # #E84BFF
INK = (8, 11, 18)          # near-black slate
INK2 = (14, 20, 32)

FONTDIR = "/mnt/c/Windows/Fonts"
OUT = os.path.join(os.path.dirname(__file__), "brand")
os.makedirs(OUT, exist_ok=True)

SS = 3  # supersample factor


def font(name, size):
    return ImageFont.truetype(os.path.join(FONTDIR, name), size)


def lerp(a, b, t):
    return tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3))


def gradient(size, c0, c1, horizontal=True):
    """A smooth two-stop gradient image (RGB)."""
    w, h = size
    if horizontal:
        base = Image.new("RGB", (w, 1))
        px = base.load()
        for x in range(w):
            px[x, 0] = lerp(c0, c1, x / max(1, w - 1))
        return base.resize((w, h))
    base = Image.new("RGB", (1, h))
    px = base.load()
    for y in range(h):
        px[0, y] = lerp(c0, c1, y / max(1, h - 1))
    return base.resize((w, h))


def hexagon(cx, cy, r, rot=-math.pi / 2):
    """Pointy-top hexagon vertices (shield-like)."""
    return [
        (cx + r * math.cos(rot + k * math.pi / 3),
         cy + r * math.sin(rot + k * math.pi / 3))
        for k in range(6)
    ]


def paste_gradient(layer, mask, c0, c1, horizontal=True):
    """Fill a mask region of `layer` (RGBA) with a gradient."""
    grad = gradient(layer.size, c0, c1, horizontal).convert("RGBA")
    layer.paste(grad, (0, 0), mask)


def tracked_text_mask(size, xy, text, fnt, tracking, anchor_center_x=None):
    """Draw letter-spaced text onto an L mask; return (mask, total_width)."""
    mask = Image.new("L", size, 0)
    d = ImageDraw.Draw(mask)
    widths = []
    for ch in text:
        bb = d.textbbox((0, 0), ch, font=fnt)
        widths.append(bb[2] - bb[0])
    total = sum(widths) + tracking * (len(text) - 1)
    x, y = xy
    if anchor_center_x is not None:
        x = anchor_center_x - total // 2
    for ch, w in zip(text, widths):
        d.text((x, y), ch, font=fnt, fill=255)
        x += w + tracking
    return mask, total


def build_mark(px=1200):
    """The hexagon-shield 'S' mark on a transparent canvas."""
    S = px * SS
    cx = cy = S // 2
    r = int(S * 0.40)

    layer = Image.new("RGBA", (S, S), (0, 0, 0, 0))

    # --- outer neon glow (two colored passes, heavily blurred) ---
    for col, blur, wdt in ((CYAN, S * 0.05, int(S * 0.03)),
                           (MAGENTA, S * 0.08, int(S * 0.02))):
        glow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
        gd = ImageDraw.Draw(glow)
        gd.line(hexagon(cx, cy, r) + [hexagon(cx, cy, r)[0]],
                fill=col + (255,), width=wdt, joint="curve")
        glow = glow.filter(ImageFilter.GaussianBlur(blur))
        layer = Image.alpha_composite(layer, glow)

    # --- double hexagon stroke, gradient filled ---
    outer = Image.new("L", (S, S), 0)
    od = ImageDraw.Draw(outer)
    poly = hexagon(cx, cy, r)
    od.line(poly + [poly[0]], fill=255, width=int(S * 0.018), joint="curve")
    inner = Image.new("L", (S, S), 0)
    ind = ImageDraw.Draw(inner)
    poly2 = hexagon(cx, cy, int(r * 0.86))
    ind.line(poly2 + [poly2[0]], fill=255, width=int(S * 0.006), joint="curve")
    stroke = Image.new("L", (S, S), 0)
    stroke.paste(outer, (0, 0), outer)
    stroke.paste(inner, (0, 0), inner)
    paste_gradient(layer, stroke, CYAN, MAGENTA, horizontal=False)

    # --- corner reticle ticks (targeting vibe), dim cyan ---
    tick = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    td = ImageDraw.Draw(tick)
    tlen = int(S * 0.05)
    tw = int(S * 0.010)
    for vx, vy in (hexagon(cx, cy, int(r * 1.10))):
        td.line([(vx - tlen, vy), (vx + tlen, vy)],
                fill=CYAN + (150,), width=tw)
    layer = Image.alpha_composite(layer, tick)

    # --- the "S" monogram, gradient filled ---
    fnt = font("consolab.ttf", int(S * 0.44))
    smask, _ = tracked_text_mask((S, S), (0, int(S * 0.24)), "S", fnt, 0,
                                 anchor_center_x=cx)
    # subtle glow behind the S
    sglow = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    sglow.paste(Image.new("RGBA", (S, S), CYAN + (255,)), (0, 0), smask)
    sglow = sglow.filter(ImageFilter.GaussianBlur(S * 0.02))
    layer = Image.alpha_composite(layer, sglow)
    paste_gradient(layer, smask, CYAN, MAGENTA, horizontal=False)

    # --- scan-line across the shield ---
    scan = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    scd = ImageDraw.Draw(scan)
    sy = int(cy + r * 0.02)
    scd.rectangle([cx - int(r * 0.72), sy - int(S * 0.004),
                   cx + int(r * 0.72), sy + int(S * 0.004)],
                  fill=CYAN + (120,))
    scan = scan.filter(ImageFilter.GaussianBlur(S * 0.004))
    layer = Image.alpha_composite(layer, scan)

    return layer.resize((px, px), Image.LANCZOS)


def build_lockup(on_dark, px_h=420):
    """Horizontal lockup: mark + SENTINEL wordmark + tagline."""
    mark = build_mark(px=px_h)
    pad = int(px_h * 0.12)
    gap = int(px_h * 0.10)

    # wordmark
    S = px_h * SS
    word_fnt = font("consolab.ttf", int(px_h * 0.42 * SS))
    tag_fnt = font("consola.ttf", int(px_h * 0.115 * SS))
    canvas_w = S * 4
    wmask, wwidth = tracked_text_mask((canvas_w, S), (0, 0), "SENTINEL",
                                      word_fnt, int(px_h * 0.05 * SS))
    tmask, twidth = tracked_text_mask((canvas_w, S), (0, 0),
                                      "AUTONOMOUS  AUTHORIZATION  RESEARCH",
                                      tag_fnt, int(px_h * 0.03 * SS))

    text_w = max(wwidth, twidth)
    total_w = px_h + gap + text_w // SS + pad * 2
    total_h = px_h + pad * 2

    if on_dark:
        base = Image.new("RGBA", (total_w, total_h), INK + (255,))
        # faint hex grid backdrop
        g = ImageDraw.Draw(base)
        for gx in range(0, total_w, 46):
            g.line([(gx, 0), (gx, total_h)], fill=INK2 + (255,), width=1)
        for gy in range(0, total_h, 46):
            g.line([(0, gy), (total_w, gy)], fill=INK2 + (255,), width=1)
    else:
        base = Image.new("RGBA", (total_w, total_h), (0, 0, 0, 0))

    # place mark
    base.alpha_composite(mark, (pad, pad))

    # render wordmark block at supersample then place
    tx = pad + px_h + gap
    block = Image.new("RGBA", (canvas_w, S), (0, 0, 0, 0))
    paste_gradient(block, wmask, CYAN, MAGENTA, horizontal=True)
    block = block.resize((canvas_w // SS, S // SS), Image.LANCZOS)
    wy = pad + int(px_h * 0.20)
    base.alpha_composite(block, (tx, wy))

    tblock = Image.new("RGBA", (canvas_w, S), (0, 0, 0, 0))
    tdraw = ImageDraw.Draw(tblock)
    tdraw.bitmap((0, 0), tmask, fill=CYAN + (255,))
    tblock = tblock.resize((canvas_w // SS, S // SS), Image.LANCZOS)
    ty = wy + int(px_h * 0.44)
    base.alpha_composite(tblock, (tx, ty))

    return base


def main():
    mark = build_mark(px=1024)
    mark.save(os.path.join(OUT, "sentinel_mark.png"))

    # square dark app-icon
    icon = Image.new("RGBA", (1024, 1024), INK + (255,))
    icon.alpha_composite(mark.resize((900, 900), Image.LANCZOS), (62, 62))
    icon.save(os.path.join(OUT, "sentinel_icon_dark.png"))

    build_lockup(on_dark=True).save(os.path.join(OUT, "sentinel_logo_dark.png"))
    build_lockup(on_dark=False).save(
        os.path.join(OUT, "sentinel_logo_transparent.png"))

    for f in sorted(os.listdir(OUT)):
        p = os.path.join(OUT, f)
        print(f, Image.open(p).size)


if __name__ == "__main__":
    main()
