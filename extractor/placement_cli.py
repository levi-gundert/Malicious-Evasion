"""Placement and offline research commands; no Triage key required."""

from dataclasses import asdict
import json
from pathlib import Path
import tempfile

import click

from extractor.placement import SafePlacement, host_os


@click.group()
@click.option(
    "--journal",
    type=click.Path(path_type=Path),
    default=Path.home() / ".evasion_artifact_placer" / "placement-journal.db",
)
@click.pass_context
def placement(ctx, journal):
    """Preview, place, inspect and undo supported exact recipes."""
    ctx.ensure_object(dict)
    ctx.obj["journal"] = journal


def read_artifact(path):
    payload = Path(path).read_bytes()
    data = json.loads(payload)  # JSON detects UTF-8/16/32 and PowerShell BOMs.
    return data.get("artifact", data)


@placement.command("plan")
@click.argument("artifact_file", type=click.Path(exists=True, path_type=Path))
def plan_command(artifact_file):
    """Resolve a recipe without writing any artifact or journal."""
    from extractor.placement import make_plan

    try:
        click.echo(
            json.dumps(asdict(make_plan(read_artifact(artifact_file))), indent=2)
        )
    except (OSError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


@placement.command("apply")
@click.argument("artifact_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--elevate", is_flag=True, help="Request OS elevation for this exact recipe."
)
@click.pass_context
def apply_command(ctx, artifact_file, elevate):
    from gui.services.placement_engine import PlacementEngine

    engine = PlacementEngine(journal_path=ctx.obj["journal"])
    if not engine.place_artifact(read_artifact(artifact_file), elevate=elevate):
        raise click.ClickException(engine.last_error)
    click.echo(
        f"Placement verified: {engine.last_token}. Malware efficacy remains untested."
    )


@placement.command("remove")
@click.argument("operation_id")
@click.option("--elevate", is_flag=True)
@click.pass_context
def remove_command(ctx, operation_id, elevate):
    from gui.services.placement_engine import PlacementEngine

    engine = PlacementEngine(journal_path=ctx.obj["journal"])
    if not engine.remove_token(operation_id, elevate=elevate):
        raise click.ClickException(engine.last_error)
    click.echo("Owned, unchanged artifact removed.")


@placement.command("status")
@click.pass_context
def status_command(ctx):
    click.echo(json.dumps(SafePlacement(ctx.obj["journal"]).reconcile(), indent=2))


@placement.command("catalog")
@click.option("--path", type=click.Path(exists=True, path_type=Path))
@click.option("--signature", type=click.Path(exists=True, path_type=Path))
@click.option("--trusted-key", type=click.Path(exists=True, path_type=Path))
@click.option("--minimum-version", type=int, default=1)
@click.option("--recipe", help="Print one artifact recipe for plan/apply.")
def catalog_command(path, signature, trusted_key, minimum_version, recipe):
    from extractor.catalog import BUNDLED, load_catalog

    try:
        catalog = load_catalog(path or BUNDLED, signature, trusted_key, minimum_version)
        if recipe:
            result = next(
                (r["artifact"] for r in catalog["recipes"] if r["name"] == recipe), None
            )
            if result is None:
                raise ValueError("Unknown recipe")
        else:
            result = catalog
        click.echo(json.dumps(result, indent=2))
    except Exception as exc:
        raise click.ClickException(f"Catalog rejected: {exc}") from exc


@placement.command("probe")
@click.option("--output", type=click.Path(path_type=Path), required=True)
def probe_command(output):
    """Benign file/directory probes in an isolated temporary directory."""
    checks = []
    with tempfile.TemporaryDirectory(prefix="meap-probe-") as directory:
        # Normalize our own workspace (macOS /var symlink, Windows 8.3 TEMP).
        # User-supplied recipe paths still go through strict path validation.
        root = Path(directory).resolve(strict=True)
        engine = SafePlacement(root / "state" / "placement-journal.db")
        for kind in ("file", "directory"):
            target = root / kind
            candidate = {
                "os": host_os(),
                "artifact_type": "file",
                "value": str(target),
                "deception": {"plant_as": kind},
            }
            before = target.exists()
            token = engine.apply(candidate)
            during = target.is_file() if kind == "file" else target.is_dir()
            engine.remove(token)
            checks.append(
                {
                    "check": kind + "_existence",
                    "absent_before": not before,
                    "present_during": during,
                    "absent_after": not target.exists(),
                }
            )
    report = {
        "host_os": host_os(),
        "scope": "Temporary-path primitive probes only; catalog targets and malware efficacy are untested",
        "checks": checks,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if not all(
        c["absent_before"] and c["present_during"] and c["absent_after"] for c in checks
    ):
        raise click.ClickException("A benign probe failed")
    click.echo(str(output.resolve()))


@placement.command("summarize-trials")
@click.argument("results_file", type=click.Path(exists=True, path_type=Path))
def summarize_command(results_file):
    """Summarize existing paired lab results; does not execute samples."""
    from extractor.validation import summarize_trials

    try:
        trials = json.loads(results_file.read_text(encoding="utf-8"))
        click.echo(json.dumps(summarize_trials(trials), indent=2))
    except (ValueError, KeyError, TypeError) as exc:
        raise click.ClickException(f"Invalid experiment: {exc}") from exc
