"""Non-destructive decoy placement with a durable ownership journal.

No report content is executed. Unknown checks fail closed. Existing parents
are required: creating an arbitrary system directory tree is not implicit.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import sqlite3
import stat
import uuid
from contextlib import contextmanager, nullcontext
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


class PlacementError(ValueError):
    pass


def host_os():
    if "ANDROID_ARGUMENT" in os.environ:
        return "android"
    return {"Windows": "windows", "Darwin": "macos", "Linux": "linux"}.get(
        platform.system(), "unknown"
    )


@dataclass(frozen=True)
class PlacementPlan:
    artifact_id: str
    os: str
    kind: str
    target: str
    registry_name: str = ""
    registry_type: str = ""
    registry_data: str | int = ""
    registry_view: int = 64


def checked_path(value: str) -> Path:
    if not value or len(value) > 2048 or any(ord(c) < 32 for c in value):
        raise PlacementError("Empty, oversized, or control-character path")
    if any(c in value for c in ("*", "?", "$", "`", '"', "<", ">", "|")):
        raise PlacementError(
            "Wildcards, unresolved variables and shell syntax are unsupported"
        )
    if re.search(r"%[^%]+%", value) or "~" in value:
        raise PlacementError("Use a fully resolved absolute path")
    if value.startswith(("\\\\", "//")):
        raise PlacementError("Network and device paths are unsupported")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path == path.parent:
        raise PlacementError("An absolute non-root path without traversal is required")
    if os.name == "nt":
        if ":" in str(path)[2:]:
            raise PlacementError("Alternate data streams are unsupported")
        for part in path.parts[1:]:
            if part.endswith((" ", ".")) or re.match(
                r"(?i)^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)", part
            ):
                raise PlacementError("Reserved Windows path")
    for component in [*reversed(path.parents), path]:
        try:
            info = component.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PlacementError("Symlinks and reparse points are unsupported")
    if not path.parent.is_dir():
        raise PlacementError(
            "Parent directory must already exist; no implicit directory creation"
        )
    return path


def make_plan(artifact: dict, current_os: str | None = None) -> PlacementPlan:
    current_os = current_os or host_os()
    if artifact.get("os") != current_os:
        raise PlacementError("Artifact OS must match this device")
    match = artifact.get("match_criteria", {})
    if artifact.get("match_type", match.get("type", "exact")) != "exact":
        raise PlacementError("Only exact checks can be placed")
    value = artifact.get("value", match.get("value", ""))
    deception = artifact.get("deception", {})
    if isinstance(deception, str):
        deception = json.loads(deception)
    if deception.get("retest_after"):
        expiry = datetime.fromisoformat(
            deception["retest_after"].replace("Z", "+00:00")
        )
        if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
            raise PlacementError(
                "Recipe is due for revalidation; placement is disabled"
            )
    kind = artifact.get("artifact_type")
    recipe = deception.get("plant_as", "") or ("file" if kind == "file" else "")
    if kind == "file" and recipe in ("file", "directory"):
        value = str(checked_path(value))
        kind = recipe
    elif (
        kind == "registry"
        and current_os == "windows"
        and recipe in ("registry_key", "registry_value")
    ):
        if not re.match(r"^(HKCU|HKLM)\\SOFTWARE\\[^\x00-\x1f]+$", value, re.I):
            raise PlacementError(
                "Only explicit HKCU/HKLM SOFTWARE recipes are supported"
            )
        subkey = value.split("\\", 2)[2].casefold()
        allowed = ("meap", "vmware, inc.", "oracle\\virtualbox guest additions")
        if not any(
            subkey == prefix or subkey.startswith(prefix + "\\") for prefix in allowed
        ):
            raise PlacementError(
                "Registry recipe is outside the reviewed decoy namespaces"
            )
        if (
            any(c in value for c in '*?/$`"<>|')
            or ".." in value.split("\\")
            or value.endswith("\\")
        ):
            raise PlacementError("Invalid registry path")
        kind = recipe
    else:
        raise PlacementError("This check has no supported reversible recipe")
    from extractor.models.id import artifact_id

    plan = PlacementPlan(
        artifact_id(current_os, artifact["artifact_type"], value),
        current_os,
        kind,
        value,
        deception.get("registry_name", ""),
        deception.get("registry_type", ""),
        deception.get("registry_data", ""),
        deception.get("registry_view", 64),
    )
    if kind == "registry_value":
        if (
            plan.registry_type not in ("REG_SZ", "REG_DWORD")
            or not plan.registry_name
            or any(ord(c) < 32 for c in plan.registry_name)
        ):
            raise PlacementError("A typed, named registry value is required")
        if plan.registry_type == "REG_DWORD" and (
            type(plan.registry_data) is not int
            or not 0 <= plan.registry_data <= 0xFFFFFFFF
        ):
            raise PlacementError("REG_DWORD data must be an unsigned 32-bit integer")
        if plan.registry_type == "REG_SZ" and (
            not isinstance(plan.registry_data, str) or "\0" in plan.registry_data
        ):
            raise PlacementError("REG_SZ data must be text without NUL")
    if plan.registry_view not in (32, 64):
        raise PlacementError("Registry view must be 32 or 64")
    return plan


class PlacementJournal:
    def __init__(self, path: Path | str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS operations (id TEXT PRIMARY KEY, plan TEXT NOT NULL, status TEXT NOT NULL, fingerprint TEXT, error TEXT, updated_at TEXT DEFAULT CURRENT_TIMESTAMP)"
            )

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=30)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def records(self):
        with self.connect() as db:
            return [
                dict(r) for r in db.execute("SELECT * FROM operations ORDER BY rowid")
            ]

    def update(self, token, status, fingerprint=None, error=""):
        with self.connect() as db:
            db.execute(
                "UPDATE operations SET status=?, fingerprint=COALESCE(?,fingerprint), error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?",
                (status, fingerprint, error, token),
            )

    def reserve(self, plan):
        encoded = json.dumps(asdict(plan), sort_keys=True)
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            for row in db.execute(
                "SELECT * FROM operations WHERE status NOT IN ('removed','failed','cancelled')"
            ):
                old = json.loads(row["plan"])
                if os.path.normcase(old["target"]) == os.path.normcase(plan.target):
                    if row["plan"] != encoded:
                        raise PlacementError(
                            "Another operation already owns this target"
                        )
                    return dict(row)
            token = str(uuid.uuid4())
            db.execute(
                "INSERT INTO operations(id,plan,status) VALUES(?,?,'pending')",
                (token, encoded),
            )
            return {
                "id": token,
                "plan": encoded,
                "status": "pending",
                "fingerprint": None,
                "new": True,
            }


def marker(token):
    return f"MEAP inert existence decoy\nOwner: {uuid.UUID(token)}\n".encode("ascii")


def fingerprint(path):
    info = path.stat(follow_symlinks=False)
    return f"{info.st_dev}:{info.st_ino}"


class SafePlacement:
    def __init__(self, journal: Path | str, current_os=None):
        self.current_os = current_os or host_os()
        self.journal = PlacementJournal(journal)

    def plan(self, artifact):
        return make_plan(artifact, self.current_os)

    def _verify(self, plan, token, identity=None):
        # Journals are data too: validate again before any elevated read/delete.
        original_type = "registry" if plan.kind.startswith("registry") else "file"
        validated = make_plan(
            {
                "os": plan.os,
                "artifact_type": original_type,
                "value": plan.target,
                "deception": {
                    "plant_as": plan.kind,
                    "registry_name": plan.registry_name,
                    "registry_type": plan.registry_type,
                    "registry_data": plan.registry_data,
                    "registry_view": plan.registry_view,
                },
            },
            self.current_os,
        )
        if validated != plan:
            raise PlacementError("Journal plan is inconsistent")
        if plan.kind.startswith("registry"):
            from extractor.registry import verify

            return verify(plan, token)
        path = checked_path(plan.target)
        if not path.exists():
            return False
        if identity and fingerprint(path) != identity:
            return False
        target = path / ".meap-owner" if plan.kind == "directory" else path
        checked_path(str(target))
        if not target.is_file() or target.stat().st_nlink != 1:
            return False
        with target.open("rb") as stream:
            return stream.read(len(marker(token)) + 1) == marker(token)

    def apply(self, artifact):
        from extractor.fsops import pinned_parents

        plan = self.plan(artifact)
        with (
            pinned_parents(plan.target)
            if not plan.kind.startswith("registry")
            else nullcontext()
        ):
            return self._apply(artifact)

    def _apply(self, artifact):
        plan = self.plan(artifact)
        row = self.journal.reserve(plan)
        token = row["id"]
        if not row.get("new"):
            if self._verify(plan, token, row["fingerprint"]):
                self.journal.update(token, "verified")
                return token
            raise PlacementError(
                "An existing operation needs reconciliation; target was preserved"
            )
        try:
            if plan.kind.startswith("registry"):
                from extractor.registry import create

                create(plan, token)
                identity = None
            else:
                path = checked_path(plan.target)
                if plan.kind == "directory":
                    path.mkdir()  # Exclusive, never adopt an existing directory.
                    self.journal.update(token, "pending", fingerprint(path))
                    target = path / ".meap-owner"
                else:
                    target = path
                with target.open("xb") as stream:
                    stream.write(marker(token))
                    stream.flush()
                    os.fsync(stream.fileno())
                identity = fingerprint(path)
            self.journal.update(token, "pending", identity)
            if not self._verify(plan, token, identity):
                raise PlacementError("Post-placement verification failed")
            self.journal.update(token, "verified")
            return token
        except FileExistsError:
            self.journal.update(token, "failed", error="Existing object preserved")
            raise PlacementError("Existing object preserved")
        except Exception as exc:
            # Leave a recoverable record even if mutation happened before failure.
            self.journal.update(token, "needs_review", error=str(exc))
            raise

    def reconcile(self):
        for row in self.journal.records():
            if row["status"] in ("removed", "failed", "cancelled"):
                continue
            plan = PlacementPlan(**json.loads(row["plan"]))
            try:
                valid = self._verify(plan, row["id"], row["fingerprint"])
                self.journal.update(
                    row["id"],
                    "verified" if valid else "needs_review",
                    error="" if valid else "Missing or changed; preserved",
                )
            except (OSError, ValueError) as exc:
                self.journal.update(row["id"], "needs_review", error=str(exc))
        return self.journal.records()

    def remove(self, token):
        from extractor.fsops import pinned_parents

        row = next((r for r in self.journal.records() if r["id"] == token), None)
        if not row or row["status"] == "removed":
            return self._remove(token)
        plan = PlacementPlan(**json.loads(row["plan"]))
        with (
            pinned_parents(plan.target)
            if not plan.kind.startswith("registry")
            else nullcontext()
        ):
            return self._remove(token)

    def _remove(self, token):
        row = next((r for r in self.journal.records() if r["id"] == token), None)
        if not row:
            raise PlacementError("No ownership record; refusing removal")
        if row["status"] == "removed":
            return True
        plan = PlacementPlan(**json.loads(row["plan"]))
        if plan.os != self.current_os:
            raise PlacementError("Journal belongs to a different OS")
        if not self._verify(plan, token, row["fingerprint"]):
            self.journal.update(
                token,
                "needs_review",
                error="Object missing, replaced, or modified; preserved",
            )
            raise PlacementError("Object missing, replaced, or modified; preserved")
        self.journal.update(token, "removing")
        if plan.kind.startswith("registry"):
            from extractor.registry import remove

            remove(plan, token)
        else:
            path = checked_path(plan.target)
            if plan.kind == "directory":
                if {p.name for p in path.iterdir()} != {".meap-owner"}:
                    self.journal.update(
                        token,
                        "needs_review",
                        error="Directory contains other data; preserved",
                    )
                    raise PlacementError("Directory contains other data; preserved")
                (path / ".meap-owner").unlink()
                path.rmdir()
            else:
                from extractor.fsops import remove_owned_file

                remove_owned_file(path, marker(token), row["fingerprint"])
        self.journal.update(token, "removed")
        return True
