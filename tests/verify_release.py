import os
import re
from pathlib import Path


source = Path(__file__).resolve().parents[1] / "browser_Gui.py"
match = re.search(r'^APP_VERSION\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', source.read_text(encoding="utf-8"), re.MULTILINE)
if match is None:
    raise SystemExit("APP_VERSION was not found in browser_Gui.py")

expected_tag = f"v{match.group(1)}"
actual_tag = os.environ.get("GITHUB_REF_NAME", "")
if actual_tag != expected_tag:
    raise SystemExit(f"APP_VERSION requires tag {expected_tag}, received {actual_tag or '<empty>'}")

print(f"Release version verified: {actual_tag}")
