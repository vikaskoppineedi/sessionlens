"""sessionlens CLI.

  python -m sessionlens start   check everything, launch capture Chrome, tell you when to browse
  python -m sessionlens view    open the analyzer on saved sessions only
  python -m sessionlens setup   redo the one-time capture profile setup
  python -m sessionlens export SESSION   (re)write sessions/SESSION/export/
"""

import argparse
import asyncio
import contextlib

from sessionlens import config, orchestrator
from sessionlens.export import write_export


def main() -> None:
    parser = argparse.ArgumentParser(prog="sessionlens")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("start")
    sub.add_parser("view")
    sub.add_parser("setup")
    export = sub.add_parser("export")
    export.add_argument("session", help="folder name under sessions/, e.g. 20260101-120000")
    args = parser.parse_args()
    if args.command == "export":
        session = config.SESSIONS_DIR / args.session
        if not (session / "events.jsonl").is_file():
            raise SystemExit(f"No session at {session}")
        export_dir = write_export(session)
        print(f"Export written: {export_dir}")
        orchestrator.say_report(export_dir)
        return
    command = {"start": orchestrator.start, "view": orchestrator.view, "setup": orchestrator.setup_profile}
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(command[args.command]())


if __name__ == "__main__":
    main()
