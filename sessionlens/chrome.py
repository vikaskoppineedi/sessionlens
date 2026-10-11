import os
from pathlib import Path


def build_chrome_command(
    chrome_path: str, profile_dir: Path, keylog_path: Path | None, urls: list[str]
) -> tuple[list[str], dict[str, str]]:
    """Plain Chrome launch. No debugging/automation flags, so the site sees a normal browser.

    SSLKEYLOGFILE makes Chrome append TLS session keys so tshark can decrypt the capture;
    it changes nothing on the wire.
    """
    argv = [
        chrome_path,
        f"--user-data-dir={profile_dir}",
        "--no-first-run",
        "--no-default-browser-check",
        *urls,
    ]
    env = dict(os.environ)
    if keylog_path is not None:
        env["SSLKEYLOGFILE"] = str(keylog_path)
    return argv, env
