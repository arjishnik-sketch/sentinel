"""
Sentinel — AI Kavach competition deck builder.

Two stages:
  1) Pillow renders premium dark "cyber" slide backgrounds (ink gradient,
     faint hex grid, soft cyan/magenta corner glows) and a cyan->magenta
     rule used as a title underline. Baked to assets/brand/.
  2) python-pptx assembles a 5-slide 16:9 deck, embedding the neon logo and
     attaching real speaker notes to every slide.

Run with a Python that has Pillow + python-pptx installed:
    python assets/build_deck.py
Output: deck/Sentinel_AI_Kavach.pptx
"""

import math
import os

from PIL import Image, ImageDraw, ImageFilter

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN, MSO_ANCHOR
from pptx.enum.shapes import MSO_SHAPE

HERE = os.path.dirname(__file__)
ROOT = os.path.dirname(HERE)
BRAND = os.path.join(HERE, "brand")
DECK = os.path.join(ROOT, "deck")
os.makedirs(DECK, exist_ok=True)

# ---- palette ----
CYAN = (34, 211, 238)
MAGENTA = (232, 75, 255)
INK_TOP = (11, 16, 26)
INK_BOT = (6, 9, 15)
GRID = (18, 27, 42)
HEXDIM = (24, 34, 52)

# pptx colors
C_CYAN = RGBColor(0x22, 0xD3, 0xEE)
C_MAGENTA = RGBColor(0xE8, 0x4B, 0xFF)
C_WHITE = RGBColor(0xEA, 0xF2, 0xFF)
C_BODY = RGBColor(0xC4, 0xD2, 0xE4)
C_DIM = RGBColor(0x6B, 0x7A, 0x90)
C_GREEN = RGBColor(0x2D, 0xD4, 0x8F)
C_AMBER = RGBColor(0xF5, 0xB3, 0x01)

W, H = 1920, 1080


# ---------- background rendering ----------
def _vgrad(size, c0, c1):
    w, h = size
    base = Image.new("RGB", (1, h))
    px = base.load()
    for y in range(h):
        t = y / max(1, h - 1)
        px[0, y] = tuple(int(c0[i] + (c1[i] - c0[i]) * t) for i in range(3))
    return base.resize((w, h))


def _hexagon(cx, cy, r, rot=-math.pi / 2):
    return [(cx + r * math.cos(rot + k * math.pi / 3),
             cy + r * math.sin(rot + k * math.pi / 3)) for k in range(6)]


def _glow(center, radius, color, alpha):
    layer = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    cx, cy = center
    d.ellipse([cx - radius, cy - radius, cx + radius, cy + radius],
              fill=color + (alpha,))
    return layer.filter(ImageFilter.GaussianBlur(radius * 0.55))


def _base_canvas():
    base = _vgrad((W, H), INK_TOP, INK_BOT).convert("RGBA")
    grid = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    gd = ImageDraw.Draw(grid)
    step = 54
    for x in range(0, W, step):
        gd.line([(x, 0), (x, H)], fill=GRID + (255,), width=1)
    for y in range(0, H, step):
        gd.line([(0, y), (W, y)], fill=GRID + (255,), width=1)
    base = Image.alpha_composite(base, grid)
    # large dim hex outlines echoing the mark, tucked in corners
    hx = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    hd = ImageDraw.Draw(hx)
    for cx, cy, r in ((-60, H + 80, 460), (W + 90, -70, 420)):
        poly = _hexagon(cx, cy, r)
        hd.line(poly + [poly[0]], fill=HEXDIM + (255,), width=3, joint="curve")
    return Image.alpha_composite(base, hx)


def render_content_bg(path):
    base = _base_canvas()
    base = Image.alpha_composite(base, _glow((150, 120), 520, CYAN, 34))
    base = Image.alpha_composite(base, _glow((W - 120, H - 90), 560, MAGENTA, 30))
    # thin neon spine on the left edge
    spine = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    sd = ImageDraw.Draw(spine)
    sd.rectangle([0, 0, 8, H], fill=CYAN + (150,))
    base = Image.alpha_composite(base, spine)
    base.convert("RGB").save(path, quality=95)


def render_title_bg(path):
    base = _base_canvas()
    base = Image.alpha_composite(base, _glow((W // 2 - 260, H // 2 - 40), 620, CYAN, 40))
    base = Image.alpha_composite(base, _glow((W // 2 + 300, H // 2 + 60), 640, MAGENTA, 38))
    # faint horizontal scanline through the centre
    scan = Image.new("RGBA", (W, H), (0, 0, 0, 0))
    scd = ImageDraw.Draw(scan)
    scd.rectangle([0, H // 2 - 2, W, H // 2 + 2], fill=CYAN + (26,))
    base = Image.alpha_composite(base, scan.filter(ImageFilter.GaussianBlur(2)))
    base.convert("RGB").save(path, quality=95)


def render_rule(path):
    w, h = 1200, 22
    bar = Image.new("RGB", (w, 1))
    px = bar.load()
    for x in range(w):
        t = x / (w - 1)
        px[x, 0] = tuple(int(CYAN[i] + (MAGENTA[i] - CYAN[i]) * t) for i in range(3))
    bar = bar.resize((w, h)).convert("RGBA")
    # round the ends with an alpha mask
    mask = Image.new("L", (w, h), 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, w - 1, h - 1], radius=h // 2, fill=255)
    bar.putalpha(mask)
    bar.save(path)


# ---------- slide content ----------
SLIDES = [
    {
        "title": "SENTINEL",
        "subtitle": "Autonomous authorization research  —  find → reason → prove",
        "bullets": [
            "Local-first AI cyber-reasoning agent for live targets",
            "Point it at any HTTP target; it runs itself",
            "Evidence-driven: a status code is never a verdict",
            "Every decision explainable and auditable",
            "Target-agnostic engine — zero target-specific code",
        ],
        "notes": (
            "This is Sentinel — an autonomous authorization-research agent for the AI "
            "Kavach challenge. You give it a live target and a cycle budget, and it recons, "
            "hypothesizes, and probes on its own, showing its reasoning the whole way. The "
            "north star is a disciplined pipeline: find, then reason, then prove — never "
            "shortcutting a raw response into a vulnerability claim."
        ),
    },
    {
        "title": "Scanners Guess. Sentinel Reasons.",
        "subtitle": "From noisy 200s to justified, tested claims",
        "bullets": [
            "Traditional scanners flag 200s — false-positive noise",
            "Authorization bugs need context, not signatures",
            "Sentinel: recon → hypotheses → adaptive research cycles",
            "Find, reason, and prove are separate stages",
            "Only reproduced policy contradictions become findings",
        ],
        "notes": (
            "Most scanners pattern-match and treat any 200 as a hit, which buries teams in "
            "false positives — and authorization flaws are exactly the class that signatures "
            "miss. Sentinel instead builds a graph of the surface, forms conservative "
            "hypotheses that are explicitly 'not yet a vulnerability,' and tests each one. A "
            "finding requires a reproduced contradiction against explicit policy, so "
            "credibility is built into the epistemics."
        ),
    },
    {
        "title": "The Caged Advisor",
        "subtitle": "Smart adaptive selection — bounded advisory AI — full provenance",
        "bullets": [
            "Deterministic score is always authoritative",
            "LLM breaks ties only — picks by index, can't invent IDs",
            "Diminishing returns: it stops beating dead hypotheses",
            "Every choice ships a human-readable rationale trail",
            "AI reasoning shown as telemetry, never as authority",
        ],
        "notes": (
            "This is our answer to 'isn't it just an LLM wrapper?' The engine scores "
            "candidates with a transparent, self-adapting formula — information gain decays "
            "as attempts repeat, so it visibly pivots off exhausted leads. The local model is "
            "consulted only when candidates tie at the top, and it picks by list index that we "
            "map back to a real id, so it can't hallucinate a target or override a higher "
            "score. Everything shows up on the decision board as auditable provenance."
        ),
    },
    {
        "title": "Inside the Loop",
        "subtitle": "recon → graph → hypotheses → decide → probe → observe → judge",
        "bullets": [
            "Recon materializes a security graph of the surface",
            "Hypotheses = justified reasons to test authorization",
            "Scope-guarded HTTP probe records facts, not verdicts",
            "Deterministic judge tests facts against explicit policy",
            "CONFIRMED-only findings; refinement feeds back in",
        ],
        "notes": (
            "Under the hood it's a clean data flow: recon feeds a security graph, hypotheses "
            "are seeded from it, and each cycle deterministically scores candidates, consults "
            "the bounded advisor on ties, then fires one scope-checked probe. Observations are "
            "structured facts with provenance back to the evidence, and only the deterministic "
            "judge can promote a hypothesis to confirmed. Refinement closes the loop, turning "
            "bare candidates into testable contradictions."
        ),
    },
    {
        "title": "Bounded Autonomy, Honest Status",
        "subtitle": "Safe by construction — and clear about what's next",
        "bullets": [
            ("ok", "Pre-connection scope guard; local, bounded, non-destructive"),
            ("ok", "The find half runs live today, end-to-end"),
            ("next", "Reason/prove built; wiring the bootstrap gap next"),
            ("cyan", "AI Kavach fit: autonomous, auditable, defensible"),
            ("cyan", "Vision: find → reason → prove → remediate"),
        ],
        "notes": (
            "Safety is structural: every probe is refused before a socket opens unless it's in "
            "scope, and the stages are separated so nothing both acts and judges. Being honest "
            "with the judges: the find-and-rank half runs live end-to-end today, while the "
            "reason-and-prove subsystem is fully built but not yet reachable autonomously — a "
            "scoped bootstrap gap that's our very next milestone. That candor, plus autonomous "
            "auditable reasoning, is exactly the AI Kavach spirit, and the road ahead adds "
            "remediation to complete the loop."
        ),
    },
]

FONT_HEAD = "Consolas"
FONT_BODY = "Segoe UI"


def _txt(slide, left, top, width, height, anchor=MSO_ANCHOR.TOP):
    tb = slide.shapes.add_textbox(Inches(left), Inches(top), Inches(width), Inches(height))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.vertical_anchor = anchor
    tf.margin_left = 0
    tf.margin_right = 0
    tf.margin_top = 0
    tf.margin_bottom = 0
    return tf


def _run(p, text, size, color, font=FONT_BODY, bold=False, spacing=None):
    r = p.add_run()
    r.text = text
    r.font.size = Pt(size)
    r.font.color.rgb = color
    r.font.name = font
    r.font.bold = bold
    return r


def _badge(slide):
    """AI KAVACH chip, top-right."""
    shp = slide.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE,
                                 Inches(11.15), Inches(0.5), Inches(1.7), Inches(0.42))
    shp.fill.background()
    shp.line.color.rgb = C_CYAN
    shp.line.width = Pt(1)
    tf = shp.text_frame
    tf.margin_top = 0
    tf.margin_bottom = 0
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    _run(p, "AI KAVACH", 12, C_CYAN, font=FONT_HEAD, bold=True)


def _footer(slide, n):
    tf = _txt(slide, 0.62, 6.98, 9.0, 0.4)
    p = tf.paragraphs[0]
    _run(p, "SENTINEL", 10, C_CYAN, font=FONT_HEAD, bold=True)
    _run(p, "   ·   find → reason → prove", 10, C_DIM, font=FONT_HEAD)
    tfn = _txt(slide, 11.8, 6.98, 1.0, 0.4)
    pn = tfn.paragraphs[0]
    pn.alignment = PP_ALIGN.RIGHT
    _run(pn, f"{n:02d} / 05", 10, C_DIM, font=FONT_HEAD)


def build():
    content_bg = os.path.join(BRAND, "deck_bg.png")
    title_bg = os.path.join(BRAND, "deck_bg_title.png")
    rule = os.path.join(BRAND, "deck_rule.png")
    render_content_bg(content_bg)
    render_title_bg(title_bg)
    render_rule(rule)

    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]

    for idx, s in enumerate(SLIDES, start=1):
        slide = prs.slides.add_slide(blank)
        is_title = idx == 1
        slide.shapes.add_picture(title_bg if is_title else content_bg, 0, 0,
                                 width=prs.slide_width, height=prs.slide_height)

        if is_title:
            # hero lockup, centred
            lock = os.path.join(BRAND, "sentinel_logo_transparent.png")
            lw = 9.2
            im = Image.open(lock)
            lh = lw * im.height / im.width
            slide.shapes.add_picture(lock, Inches((13.333 - lw) / 2), Inches(1.55),
                                     width=Inches(lw))
            sub = _txt(slide, 1.5, 1.7 + lh, 10.333, 0.6)
            ps = sub.paragraphs[0]
            ps.alignment = PP_ALIGN.CENTER
            _run(ps, s["subtitle"], 19, C_CYAN, font=FONT_HEAD)
            body = _txt(slide, 1.9, 2.35 + lh, 9.533, 2.2)
            for i, b in enumerate(s["bullets"]):
                p = body.paragraphs[0] if i == 0 else body.add_paragraph()
                p.alignment = PP_ALIGN.CENTER
                p.space_after = Pt(7)
                _run(p, b, 15, C_BODY, font=FONT_BODY)
            foot = _txt(slide, 0, 6.85, 13.333, 0.5)
            pf = foot.paragraphs[0]
            pf.alignment = PP_ALIGN.CENTER
            _run(pf, "AI KAVACH CHALLENGE  ·  AUTONOMOUS CYBER-REASONING", 11,
                 C_DIM, font=FONT_HEAD, bold=True)
        else:
            slide.shapes.add_picture(os.path.join(BRAND, "sentinel_mark.png"),
                                     Inches(0.62), Inches(0.5), width=Inches(0.82))
            _badge(slide)
            # title
            tt = _txt(slide, 1.65, 0.52, 9.3, 1.15, anchor=MSO_ANCHOR.MIDDLE)
            pt = tt.paragraphs[0]
            _run(pt, s["title"], 33, C_WHITE, font=FONT_HEAD, bold=True)
            # gradient rule + subtitle
            slide.shapes.add_picture(rule, Inches(0.7), Inches(1.82),
                                     width=Inches(3.4), height=Inches(0.062))
            st = _txt(slide, 0.72, 2.02, 11.9, 0.6)
            pst = st.paragraphs[0]
            _run(pst, s["subtitle"], 17, C_CYAN, font=FONT_HEAD)
            # bullets
            bt = _txt(slide, 0.78, 2.95, 11.8, 3.7)
            for i, b in enumerate(s["bullets"]):
                if isinstance(b, tuple):
                    kind, text = b
                else:
                    kind, text = "cyan", b
                glyph, gcol, tcol = {
                    "ok": ("»", C_GREEN, C_WHITE),
                    "next": ("»", C_AMBER, C_WHITE),
                    "cyan": ("»", C_CYAN, C_BODY),
                }[kind]
                p = bt.paragraphs[0] if i == 0 else bt.add_paragraph()
                p.space_after = Pt(15)
                _run(p, glyph + "  ", 19, gcol, font=FONT_BODY, bold=True)
                _run(p, text, 19, tcol, font=FONT_BODY)
            _footer(slide, idx)

        slide.notes_slide.notes_text_frame.text = s["notes"]

    out = os.path.join(DECK, "Sentinel_AI_Kavach.pptx")
    prs.save(out)
    print("wrote", out)
    print("slides:", len(prs.slides._sldIdLst))


if __name__ == "__main__":
    build()
