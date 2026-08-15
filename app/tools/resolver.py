from pathlib import Path
import shutil


def resolve(tool: str) -> str:
    """
    Resolve the full path to a tool.

    Search order:
    1. PATH
    2. ~/go/bin
    """

    binary = shutil.which(tool)

    if binary:
        return binary

    candidate = Path.home() / "go" / "bin" / tool

    if candidate.exists():
        return str(candidate)

    raise FileNotFoundError(
        f"{tool} executable not found.\n"
        f"Tried PATH and {candidate}"
    )