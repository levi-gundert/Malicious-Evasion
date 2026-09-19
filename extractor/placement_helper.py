"""Narrow elevated entry point. Input is data, never script text."""

import base64
import json
from pathlib import Path
import sys

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from extractor.placement import SafePlacement, host_os


def execute(request):
    if set(request) - {"action", "artifact", "token", "journal"}:
        raise ValueError("Unknown request fields")
    journal = Path(request["journal"])
    if not journal.is_absolute() or journal.name != "placement-journal.db":
        raise ValueError("Invalid journal path")
    for component in (journal, *journal.parents):
        if component.is_symlink() or (
            component.exists()
            and getattr(component.lstat(), "st_file_attributes", 0) & 0x400
        ):
            raise ValueError("Journal must not traverse a link")
    engine = SafePlacement(journal, host_os())
    if request["action"] == "place":
        return engine.apply(request["artifact"])
    if request["action"] == "remove":
        return engine.remove(request["token"])
    raise ValueError("Unsupported operation")


def main():
    try:
        if len(sys.argv) != 2 or len(sys.argv[1]) > 32768:
            raise ValueError("Invalid request size")
        request = json.loads(base64.b64decode(sys.argv[1], validate=True))
        execute(request)
        return 0
    except Exception as exc:
        print(f"Placement failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
