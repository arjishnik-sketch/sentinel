from pathlib import Path
from dotenv import load_dotenv
import logging
import os
import sys

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent

REPORTS_DIR = BASE_DIR / "reports"
MEMORY_DIR = BASE_DIR / "memory"
PROMPTS_DIR = BASE_DIR / "prompts"

REPORTS_DIR.mkdir(exist_ok=True)
MEMORY_DIR.mkdir(exist_ok=True)
PROMPTS_DIR.mkdir(exist_ok=True)

DATABASE = Path.home() / ".sentinel.db"

OLLAMA_URL = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen3:4b")

REQUEST_TIMEOUT = int(
    os.getenv("REQUEST_TIMEOUT", "600")
)

# The research advisor is a bounded, per-cycle tiebreak. It must never
# stall the autonomous loop, so it gets its own short timeout that is
# independent of the long-form analysis REQUEST_TIMEOUT. On timeout the
# engine falls back to deterministic selection.
AI_ADVISORY_TIMEOUT = int(
    os.getenv("AI_ADVISORY_TIMEOUT", "30")
)

# Bounded generation budget for the advisory JSON response. On a local
# CPU model, wall-clock is dominated by output tokens, so this cap is the
# main latency lever. The advisor is asked for a single-pick response
# (one candidate id + a short reason + a confidence), which comfortably
# fits well under this ceiling; the cap only bounds a misbehaving model.
AI_ADVISORY_NUM_PREDICT = int(
    os.getenv("AI_ADVISORY_NUM_PREDICT", "128")
)

# The advisor is a tiebreak among the equally top-scored candidates, so it
# only needs to see that tied band — never the full frontier. Capping the
# candidate payload (and, with it, the hypotheses/observations projected
# alongside) keeps each per-cycle prompt small enough to stay well under
# the model context window, which is what actually drives latency.
AI_ADVISORY_MAX_CANDIDATES = int(
    os.getenv("AI_ADVISORY_MAX_CANDIDATES", "12")
)

MAX_AI_INPUT = int(
    os.getenv("MAX_AI_INPUT", "15000")
)

LOG_LEVEL = os.getenv(
    "LOG_LEVEL",
    "INFO"
).upper()

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger("Sentinel")


def validate():

    missing = []

    if not OLLAMA_URL:
        missing.append("OLLAMA_URL")

    if not OLLAMA_MODEL:
        missing.append("OLLAMA_MODEL")

    if missing:

        logger.error(
            "Missing configuration: %s",
            ", ".join(missing)
        )

        sys.exit(1)

    logger.info("Configuration loaded successfully.")

    logger.info("Model : %s", OLLAMA_MODEL)
    logger.info("Ollama : %s", OLLAMA_URL)
    logger.info("Database : %s", DATABASE)

    return True


if __name__ == "__main__":

    validate()

    print()

    print("=" * 45)
    print(" Sentinel Configuration")
    print("=" * 45)

    print(f"Model      : {OLLAMA_MODEL}")
    print(f"Ollama URL : {OLLAMA_URL}")
    print(f"Database   : {DATABASE}")
    print(f"Reports    : {REPORTS_DIR}")
    print(f"Memory     : {MEMORY_DIR}")
    print(f"Prompts    : {PROMPTS_DIR}")

    print()

    print("Configuration OK ✅")
