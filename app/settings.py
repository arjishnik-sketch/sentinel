from pathlib import Path
import yaml

CONFIG = Path(__file__).parent.parent / "config" / "config.yaml"

with open(CONFIG, "r") as f:
    SETTINGS = yaml.safe_load(f)

def get(path, default=None):
    obj = SETTINGS
    for part in path.split("."):
        if not isinstance(obj, dict):
            return default
        obj = obj.get(part)
        if obj is None:
            return default
    return obj

if __name__ == "__main__":
    print(get("general.model"))
    print(get("pipeline.subfinder"))
