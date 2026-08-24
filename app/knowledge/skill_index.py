"""Knowledge base of security skills — a compact, queryable index over the
Anthropic Cybersecurity Skills collection (817 skills, Apache-2.0).

PROVENANCE / ATTRIBUTION: the underlying skill definitions are the "Anthropic
Cybersecurity Skills" collection, licensed Apache-2.0. This module ships only a
DERIVED METADATA index (name/description/domain/subdomain/tags/mitre) — never the
skill bodies — built by :func:`build_index` from a local checkout and cached to
``data/skill_index.json`` so the runtime is self-contained and offline. Sentinel
is not affiliated with or endorsed by Anthropic.

The index is a KB HINT source only: :class:`SkillIndex` ranks cards by relevance
to an observed :class:`~app.autonomous.surface.Surface`, and the orchestrator
feeds the top cards to qwen as breadth hints. Skills never become findings — the
rule floor and the pure judges remain the guarantees.
"""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

_DATA_PATH = os.path.join(os.path.dirname(__file__), "data", "skill_index.json")

# Always-on web/appsec bias, plus per-capability query terms derived from a
# Surface. Selection is heuristic breadth only — deterministic and safe.
_BASE_WEB_TERMS = (
    "web", "web-application", "appsec", "injection", "authentication",
    "authorization", "api",
)
_FLAG_TERMS = {
    "has_login": ("authentication", "login", "session", "credential", "auth"),
    "has_graphql": ("graphql", "api", "introspection"),
    "has_swagger": ("api", "openapi", "swagger", "rest"),
    "has_uploads": ("file-upload", "upload", "file"),
    "is_spa": ("javascript", "dom", "spa", "client-side"),
}


@dataclass(frozen=True)
class SkillCard:
    name: str
    description: str = ""
    domain: str = ""
    subdomain: str = ""
    tags: tuple = ()
    mitre: tuple = ()
    path: str = ""

    @property
    def haystack(self) -> str:
        parts = [self.name, self.description, self.subdomain]
        parts.extend(self.tags)
        parts.extend(self.mitre)
        return " ".join(str(p) for p in parts).lower()


def _card_from_dict(d):
    return SkillCard(
        name=str(d.get("name", "")),
        description=str(d.get("description", "")),
        domain=str(d.get("domain", "")),
        subdomain=str(d.get("subdomain", "")),
        tags=tuple(d.get("tags", ()) or ()),
        mitre=tuple(d.get("mitre", ()) or ()),
        path=str(d.get("path", "")),
    )


def surface_terms(surface):
    """Derive lowercased query terms from an observed surface: always the web/
    appsec base, plus per-capability terms, plus the fingerprinted tech tokens."""
    terms = list(_BASE_WEB_TERMS)
    for flag, extra in _FLAG_TERMS.items():
        if getattr(surface, flag, False):
            terms.extend(extra)
    for tech in getattr(surface, "techs", ()) or ():
        tok = str(tech).strip().lower()
        if tok:
            terms.append(tok)
    # de-dup, preserve order
    seen, out = set(), []
    for t in terms:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return tuple(out)


class SkillIndex:
    """In-memory, queryable KB index. Load the packaged JSON via :meth:`load`."""

    def __init__(self, cards):
        self.cards = tuple(cards)

    def __len__(self):
        return len(self.cards)

    @classmethod
    def from_dicts(cls, dicts):
        return cls(_card_from_dict(d) for d in dicts)

    @classmethod
    def from_json(cls, path=None):
        path = path or _DATA_PATH
        with open(path, "r", encoding="utf-8") as fh:
            blob = json.load(fh)
        return cls.from_dicts(blob.get("skills", []))

    @classmethod
    def load(cls):
        """Packaged index if present, else an empty index (KB is optional)."""
        try:
            return cls.from_json()
        except (OSError, ValueError):
            return cls(())

    def _score(self, card, terms):
        hay = card.haystack
        # tags/subdomain overlap weighted above a mere description mention
        weighted = " ".join([card.subdomain] + list(card.tags)).lower()
        score = 0
        for t in terms:
            if t in weighted:
                score += 2
            elif t in hay:
                score += 1
        return score

    def select(self, terms, *, limit=12):
        """Rank cards by overlap with ``terms``; drop zero-score; deterministic."""
        terms = tuple(str(t).lower() for t in terms)
        scored = [(self._score(c, terms), c) for c in self.cards]
        scored = [(s, c) for s, c in scored if s > 0]
        scored.sort(key=lambda sc: (-sc[0], sc[1].name))
        return [c for _s, c in scored[:limit]]

    def select_for_surface(self, surface, *, limit=12):
        return self.select(surface_terms(surface), limit=limit)


# ---- dev-time builder (reads a local checkout; not needed at runtime) --------

def parse_frontmatter(text):
    """Extract the leading YAML frontmatter block (between the first two '---')."""
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}
    body = []
    for line in lines[1:]:
        if line.strip() == "---":
            break
        body.append(line)
    import yaml  # available in dev; runtime uses the prebuilt JSON
    data = yaml.safe_load("\n".join(body))
    return data if isinstance(data, dict) else {}


def _as_list(value):
    if value is None:
        return ()
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value)
    return (str(value),)


def build_index(skills_root):
    """Walk ``skills_root`` for SKILL.md files and build cards from frontmatter."""
    cards = []
    for root, _dirs, files in os.walk(skills_root):
        for fname in files:
            if fname != "SKILL.md":
                continue
            full = os.path.join(root, fname)
            try:
                with open(full, "r", encoding="utf-8") as fh:
                    fm = parse_frontmatter(fh.read())
            except (OSError, ValueError):
                continue
            name = str(fm.get("name") or os.path.basename(root))
            cards.append(
                SkillCard(
                    name=name,
                    description=str(fm.get("description", "")),
                    domain=str(fm.get("domain", "")),
                    subdomain=str(fm.get("subdomain", "")),
                    tags=_as_list(fm.get("tags")),
                    mitre=_as_list(fm.get("mitre_attack")),
                    path=os.path.relpath(full, skills_root).replace(os.sep, "/"),
                )
            )
    cards.sort(key=lambda c: c.name)
    return cards


def write_json(cards, path=None):
    path = path or _DATA_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    blob = {
        "version": 1,
        "source": "Anthropic Cybersecurity Skills",
        "license": "Apache-2.0",
        "attribution": "Derived metadata index; skill bodies not included. Not affiliated with Anthropic.",
        "count": len(cards),
        "skills": [
            {
                "name": c.name,
                "description": c.description,
                "domain": c.domain,
                "subdomain": c.subdomain,
                "tags": list(c.tags),
                "mitre": list(c.mitre),
                "path": c.path,
            }
            for c in cards
        ],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(blob, fh, ensure_ascii=False, indent=1, sort_keys=False)
    return path


