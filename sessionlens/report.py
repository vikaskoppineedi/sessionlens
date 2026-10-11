"""Standalone export/index.html: the built analyzer UI with the session's data embedded, no server needed."""

import html
import json
import re
from pathlib import Path
from typing import Any

Json = dict[str, Any]
_SCRIPT = re.compile(r'<script type="module"[^>]*src="/assets/([^"]+\.js)"[^>]*></script>')
_STYLE = re.compile(r'<link rel="stylesheet"[^>]*href="/assets/([^"]+\.css)"[^>]*>')
_ICON = re.compile(r'\s*<link rel="icon"[^>]*>')
_TITLE = re.compile(r"<title>.*?</title>", re.S)


def build_report(data: Json, dist_dir: Path) -> str | None:
    """Inline the built UI's JS and CSS around `data`; None when the UI isn't built."""
    index = dist_dir / "index.html"
    if not index.is_file():
        return None
    page = index.read_text()
    script, style = _SCRIPT.search(page), _STYLE.search(page)
    if not script or not style:
        return None
    # Inside <script>, only "</script" (and "<!--") can end the element early; "<\/" means the same to JS and JSON.
    js = (dist_dir / "assets" / script.group(1)).read_text().replace("</script", "<\\/script")
    css = (dist_dir / "assets" / style.group(1)).read_text()
    blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")
    scripts = (f'<script id="sessionlens-data" type="application/json">{blob}</script>\n'
               f'    <script type="module">{js}</script>')  # fmt: skip
    page = _SCRIPT.sub(lambda _: scripts, page, count=1)
    page = _STYLE.sub(lambda _: f"<style>{css}</style>", page, count=1)
    page = _ICON.sub("", page)
    return _TITLE.sub(lambda _: f"<title>SessionLens · {html.escape(str(data['session']))}</title>", page, count=1)
