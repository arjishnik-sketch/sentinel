from pathlib import Path
from dataclasses import dataclass
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


@dataclass(frozen=True)
class InstallRecipe:
    """A DECLARED way to obtain a tool. Identifying the tool + command is
    Sentinel's job; actually running it always requires user approval upstream
    (see app/tools/runner.ensure_available). This object never runs anything."""

    tool: str
    manager: str          # "go" | "pip" | "pipx" | "git" | "apt" | "brew"
    command: tuple        # argv to execute, e.g. ("go", "install", "...@latest")
    note: str = ""

    @property
    def display(self) -> str:
        return " ".join(self.command)


# Curated, pinned-where-sane install recipes for the recon/exploit tools the
# engine knows how to drive. Go tools land in ~/go/bin (already on resolve()'s
# search path). Everything here is well-known, actively-maintained OSS.
INSTALL_RECIPES = {
    "subfinder": InstallRecipe("subfinder", "go", ("go", "install", "-v", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"), "ProjectDiscovery subdomain enumerator"),
    "httpx": InstallRecipe("httpx", "go", ("go", "install", "-v", "github.com/projectdiscovery/httpx/cmd/httpx@latest"), "ProjectDiscovery HTTP prober"),
    "katana": InstallRecipe("katana", "go", ("go", "install", "-v", "github.com/projectdiscovery/katana/cmd/katana@latest"), "ProjectDiscovery crawler (JS-aware)"),
    "nuclei": InstallRecipe("nuclei", "go", ("go", "install", "-v", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"), "ProjectDiscovery template scanner"),
    "dnsx": InstallRecipe("dnsx", "go", ("go", "install", "-v", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"), "ProjectDiscovery DNS toolkit"),
    "ffuf": InstallRecipe("ffuf", "go", ("go", "install", "github.com/ffuf/ffuf/v2@latest"), "content/parameter fuzzer"),
    "gau": InstallRecipe("gau", "go", ("go", "install", "github.com/lc/gau/v2/cmd/gau@latest"), "getallurls (wayback/otx/commoncrawl)"),
    "waybackurls": InstallRecipe("waybackurls", "go", ("go", "install", "github.com/tomnomnom/waybackurls@latest"), "wayback URL harvester"),
    "dalfox": InstallRecipe("dalfox", "go", ("go", "install", "github.com/hahwul/dalfox/v2@latest"), "XSS scanner"),
    "arjun": InstallRecipe("arjun", "pip", ("pip", "install", "--upgrade", "arjun"), "HTTP parameter discovery"),
    "wafw00f": InstallRecipe("wafw00f", "pip", ("pip", "install", "--upgrade", "wafw00f"), "WAF fingerprinter"),
    "sqlmap": InstallRecipe("sqlmap", "pip", ("pip", "install", "--upgrade", "sqlmap"), "automated SQL injection"),
}


def plan_install(tool: str):
    """Return the InstallRecipe for `tool`, or None if we don't know how to get
    it. Pure lookup — never executes. The caller decides whether to ask the user
    and run it."""

    return INSTALL_RECIPES.get(tool)
