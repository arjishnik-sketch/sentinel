import logging
from pathlib import Path
from datetime import datetime
from .settings import get

LOG_DIR = Path(get("logging.directory", "logs"))
LOG_DIR.mkdir(exist_ok=True)

logfile = LOG_DIR / f"{datetime.now().strftime('%Y-%m-%d')}.log"

logger = logging.getLogger("Sentinel")

if not logger.handlers:

    level = getattr(
        logging,
        get("logging.level", "INFO").upper(),
        logging.INFO
    )

    logger.setLevel(level)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(message)s"
    )

    fh = logging.FileHandler(logfile)
    fh.setFormatter(formatter)

    sh = logging.StreamHandler()
    sh.setFormatter(formatter)

    logger.addHandler(fh)
    logger.addHandler(sh)

if __name__ == "__main__":

    logger.info("Recon started")
    logger.warning("Katana timeout")
    logger.error("HTTPX failed")
