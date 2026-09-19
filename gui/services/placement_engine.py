"""GUI adapter for the shared, journaled placement backend."""

import json
from dataclasses import asdict
from pathlib import Path
from extractor.placement import SafePlacement, PlacementError, host_os


class PlacementEngine:
    def __init__(self, current_os=None, journal_path=None):
        self.current_os = current_os or host_os()
        self.core = SafePlacement(
            journal_path
            or Path.home() / ".evasion_artifact_placer" / "placement-journal.db",
            self.current_os,
        )
        self.last_error = ""
        self.last_token = None

    def plan(self, artifact):
        return self.core.plan(artifact)

    def place_artifact(self, artifact, elevate=False):
        self.last_error = ""
        try:
            plan = self.plan(artifact)
            if elevate:
                from gui.services.elevation import run_helper

                if not run_helper(
                    {
                        "action": "place",
                        "artifact": artifact,
                        "journal": str(self.core.journal.path.resolve()),
                    },
                    self.current_os,
                ):
                    raise PlacementError(
                        "Elevation cancelled or helper failed; inspect placement history"
                    )
                rows = self.core.reconcile()
                row = next(
                    (
                        r
                        for r in reversed(rows)
                        if json.loads(r["plan"]) == asdict(plan)
                        and r["status"] == "verified"
                    ),
                    None,
                )
                if row is None:
                    raise PlacementError(
                        "Helper completed but placement could not be verified"
                    )
                self.last_token = row["id"]
            else:
                self.last_token = self.core.apply(artifact)
            return True
        except Exception as exc:
            self.last_error = str(exc)
            return False

    def remove_token(self, token, elevate=False):
        self.last_error = ""
        try:
            if elevate:
                from gui.services.elevation import run_helper

                ok = run_helper(
                    {
                        "action": "remove",
                        "token": token,
                        "journal": str(self.core.journal.path.resolve()),
                    },
                    self.current_os,
                )
                row = next(
                    (r for r in self.core.journal.records() if r["id"] == token), {}
                )
                if not ok or row.get("status") != "removed":
                    raise PlacementError(
                        "Removal cancelled or failed; object preserved for review"
                    )
                return True
            return self.core.remove(token)
        except Exception as exc:
            self.last_error = str(exc)
            return False

    def remove_artifact(self, artifact, placed_path=None):
        # Legacy paths alone never establish ownership.
        token = artifact.get("operation_id")
        if not token:
            self.last_error = (
                "Legacy placement has no ownership proof; manual review required"
            )
            return False
        return self.remove_token(token)

    def get_user_space_path(self, artifact):
        return None  # Relocation would change the semantics of an exact path check.
