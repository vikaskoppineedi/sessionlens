import os
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
EXTENSION_DIR = REPO_ROOT / "extension"
WEB_DIST_DIR = REPO_ROOT / "web" / "dist"
# Captures hold tokens and packet captures, so they live outside the code repo.
# Override with SESSIONLENS_CAPTURES=/some/folder.
SESSIONS_DIR = Path(os.environ.get("SESSIONLENS_CAPTURES", "~/sessionlens-captures")).expanduser()
# The capture profile always lives at the same path: Chrome signs its settings with the path,
# so restoring the pristine copy in place keeps the extension enabled.
CAPTURE_PROFILE_DIR = REPO_ROOT / "profiles" / "capture"
PRISTINE_PROFILE_DIR = REPO_ROOT / "profiles" / "capture.pristine"

CHROME_PATH = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

# Pinned by the "key" field in extension/manifest.json.
EXTENSION_ID = "lolplpifjgedgnnbcpcpkkinmiknnjfl"
EXTENSION_ORIGIN = f"chrome-extension://{EXTENSION_ID}"

# Loopback only: nothing else on the network can feed events in.
INGEST_HOST = "127.0.0.1"
INGEST_PORT = 8765
# The analyzer is reachable from other devices on the LAN, with no password: home network only.
UI_HOST = "0.0.0.0"
UI_PORT = 47831

CAPTURE_INTERFACES = ["en0"]  # Wi-Fi; localhost is only other apps on this Mac
DISK_POLL_SECONDS = 2.0
