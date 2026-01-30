from pathlib import Path
from typing import Optional

import click

from extractor.config import ConfigError, load_config
from extractor.logging import init_logging

# Commands that need config loaded
CONFIG_COMMANDS = {
    "extract",
    "extract-sample",
    "stats",
    "clear-cache",
    "validate-config",
    "generate-deception",
}


@click.group()
@click.option(
    "--config",
    "config_path",
    type=click.Path(dir_okay=False, path_type=str),
    default=None,
    help="Path to config file (default: ./config.yaml or EXTRACTOR_CONFIG).",
)
@click.pass_context
def cli(ctx: click.Context, config_path: Optional[str]) -> None:
    """Triage Artifact Extractor CLI."""
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config_path

    if ctx.resilient_parsing:
        return

    if ctx.invoked_subcommand in CONFIG_COMMANDS:
        try:
            config = load_config(config_path)
        except (ConfigError, FileNotFoundError) as exc:
            raise click.ClickException(str(exc)) from exc
        init_logging(config.logging)
        ctx.obj["config"] = config


@cli.command()
def version() -> None:
    """Print version information."""
    click.echo("Triage Artifact Extractor v1.0")


@cli.command()
@click.option(
    "--os",
    "os_filter",
    multiple=True,
    help="OS types to extract (android, windows, linux, macos). Can be specified multiple times.",
)
@click.option(
    "--output",
    "-o",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("./output"),
    help="Output directory for results (default: ./output).",
)
@click.option(
    "--min-confidence",
    type=float,
    default=0.0,
    help="Minimum confidence threshold (0.0-1.0, default: 0.0).",
)
@click.option(
    "--min-samples",
    type=int,
    default=1,
    help="Minimum sample count threshold (default: 1).",
)
@click.option(
    "--no-split",
    is_flag=True,
    help="Don't write per-OS JSON files.",
)
@click.option(
    "--no-deception",
    is_flag=True,
    help="Don't generate deception YAML configs.",
)
@click.pass_context
def extract(
    ctx: click.Context,
    os_filter: tuple[str, ...],
    output_dir: Path,
    min_confidence: float,
    min_samples: int,
    no_split: bool,
    no_deception: bool,
) -> None:
    """
    Extract artifacts from local fixtures.
    
    This command processes captured Triage fixtures and generates
    artifact databases and deception configurations.
    
    Examples:
    
        # Extract all OS types
        python -m extractor.cli extract
        
        # Extract only Android artifacts
        python -m extractor.cli extract --os android
        
        # Extract with filtering
        python -m extractor.cli extract --min-confidence 0.3 --min-samples 2
    """
    from extractor.pipeline import run_extraction_pipeline
    
    # Debug: Log parameters
    click.echo(f"Extracting artifacts...")
    click.echo(f"  OS filter: {list(os_filter) if os_filter else 'all'}")
    click.echo(f"  Output: {output_dir}")
    click.echo(f"  Min confidence: {min_confidence}")
    click.echo(f"  Min samples: {min_samples}")
    click.echo()
    
    try:
        summary = run_extraction_pipeline(
            output_dir=output_dir,
            os_filter=list(os_filter) if os_filter else None,
            min_confidence=min_confidence,
            min_sample_count=min_samples,
            split_by_os=not no_split,
            generate_deception=not no_deception,
        )
        
        # Print summary
        click.echo("=" * 60)
        click.echo("EXTRACTION COMPLETE")
        click.echo("=" * 60)
        click.echo(f"Extraction ID: {summary['extraction_id']}")
        click.echo(f"Total artifacts: {summary['statistics']['total_artifacts']}")
        
        if summary['statistics']['by_os']:
            click.echo("\nBy OS:")
            for os_name, count in summary['statistics']['by_os'].items():
                click.echo(f"  {os_name}: {count}")
        
        if summary['errors'] > 0:
            click.echo(f"\nErrors: {summary['errors']}")
        
        click.echo("\nOutput files:")
        for file_type, files in summary['output_files'].items():
            for f in files:
                click.echo(f"  {f}")
        
    except Exception as e:
        raise click.ClickException(f"Extraction failed: {e}")


@cli.command("extract-sample")
@click.argument("sample_id")
@click.option(
    "--os",
    "os_type",
    type=click.Choice(["android", "windows", "linux", "macos"]),
    help="Override OS detection.",
)
@click.option(
    "--output",
    "-o",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("./output"),
    help="Output directory for results (default: ./output).",
)
@click.pass_context
def extract_sample(
    ctx: click.Context,
    sample_id: str,
    os_type: Optional[str],
    output_dir: Path,
) -> None:
    """
    Extract artifacts from a single sample in fixtures.
    
    SAMPLE_ID is the Triage sample identifier (e.g., 260128-w7lkgaazpc).
    
    Examples:
    
        # Extract from a known Android sample
        python -m extractor.cli extract-sample 260128-w7lkgaazpc --os android
    """
    from extractor.testing.fixtures import (
        load_overview,
        load_behavioral_report,
        load_kernel_logs,
        has_kernel_logs,
        list_fixture_os,
        list_fixture_samples,
    )
    from extractor.pipeline import extract_sample as do_extract, write_outputs
    from extractor.models.artifact import OSType
    
    click.echo(f"Extracting from sample: {sample_id}")
    
    # Find which OS the sample belongs to
    found_os = None
    for os_name in list_fixture_os():
        if sample_id in list_fixture_samples(os_name):
            found_os = os_name
            break
    
    if found_os is None:
        raise click.ClickException(
            f"Sample {sample_id} not found in fixtures.\n"
            "Run 'python scripts/capture_fixtures.py' to capture fixtures first."
        )
    
    click.echo(f"Found in: {found_os}")
    
    try:
        # Load data
        overview = load_overview(found_os, sample_id)
        behavioral = load_behavioral_report(found_os, sample_id, "behavioral1")
        
        kernel_logs = None
        if has_kernel_logs(found_os, sample_id, "behavioral1"):
            kernel_logs = load_kernel_logs(found_os, sample_id, "behavioral1")
            click.echo("Kernel logs: available")
        else:
            click.echo("Kernel logs: not available (using signatures)")
        
        # Parse OS type override
        os_override = None
        if os_type:
            os_override = OSType(os_type)
        
        # Extract
        result = do_extract(
            overview=overview,
            behavioral_report=behavioral,
            kernel_logs=kernel_logs,
            os_type=os_override,
        )
        
        click.echo(f"\nExtracted {result.statistics.total_artifacts} artifacts")
        
        if result.errors:
            click.echo(f"Errors: {len(result.errors)}")
            for err in result.errors:
                click.echo(f"  - {err.sample_id}: {err.error}")
        
        # Write outputs
        if result.statistics.total_artifacts > 0:
            written = write_outputs(
                result=result,
                output_dir=output_dir,
                split_by_os=True,
                generate_deception=True,
            )
            
            click.echo("\nOutput files:")
            for files in written.values():
                for f in files:
                    click.echo(f"  {f}")
        else:
            click.echo("\nNo artifacts to write.")
        
    except Exception as e:
        raise click.ClickException(f"Extraction failed: {e}")


@cli.command("validate-config")
@click.pass_context
def validate_config(ctx: click.Context) -> None:
    """Validate the configuration file."""
    config = ctx.obj.get("config")
    if config:
        click.echo("Configuration is valid!")
        click.echo(f"  Output directory: {config.output.directory}")
        click.echo(f"  Log level: {config.logging.level}")
        click.echo(f"  OS targets: {[t.value for t in config.extraction.os_targets]}")
    else:
        click.echo("No configuration loaded.")


@cli.command("extract-live")
@click.option(
    "--api-key",
    envvar="TRIAGE_API_KEY",
    help="Triage API key (or set TRIAGE_API_KEY env var).",
)
@click.option(
    "--os",
    "os_filter",
    multiple=True,
    default=["android"],
    help="OS types to search (default: android). Can be specified multiple times.",
)
@click.option(
    "--output",
    "-o",
    "output_dir",
    type=click.Path(path_type=Path),
    default=Path("./output"),
    help="Output directory for results (default: ./output).",
)
@click.option(
    "--min-score",
    type=int,
    default=5,
    help="Minimum sample score to include (default: 5).",
)
@click.option(
    "--days",
    type=int,
    default=7,
    help="Look back period in days (default: 7).",
)
@click.option(
    "--max-samples",
    type=int,
    default=10,
    help="Maximum samples per OS to process (default: 10).",
)
@click.option(
    "--min-confidence",
    type=float,
    default=0.0,
    help="Minimum confidence threshold for output (0.0-1.0, default: 0.0).",
)
@click.option(
    "--no-split",
    is_flag=True,
    help="Don't write per-OS JSON files.",
)
@click.option(
    "--no-deception",
    is_flag=True,
    help="Don't generate deception YAML configs.",
)
def extract_live(
    api_key: Optional[str],
    os_filter: tuple[str, ...],
    output_dir: Path,
    min_score: int,
    days: int,
    max_samples: int,
    min_confidence: float,
    no_split: bool,
    no_deception: bool,
) -> None:
    """
    Extract artifacts from live Triage API.
    
    Searches for recent samples with evasion behavior and extracts
    artifacts that malware uses to detect analysis environments.
    
    Requires TRIAGE_API_KEY environment variable or --api-key option.
    
    Examples:
    
        # Set API key and extract Android samples
        $env:TRIAGE_API_KEY = "your-key"
        python -m extractor.cli extract-live --os android
        
        # Extract from multiple OS types
        python -m extractor.cli extract-live --os android --os windows
        
        # Extract more samples with lower score threshold
        python -m extractor.cli extract-live --max-samples 50 --min-score 3
    """
    from extractor.pipeline import run_live_extraction_pipeline
    
    if not api_key:
        raise click.ClickException(
            "API key required. Set TRIAGE_API_KEY environment variable or use --api-key."
        )
    
    click.echo("=" * 60)
    click.echo("LIVE TRIAGE API EXTRACTION")
    click.echo("=" * 60)
    click.echo(f"OS filter: {list(os_filter)}")
    click.echo(f"Min score: {min_score}")
    click.echo(f"Days: {days}")
    click.echo(f"Max samples per OS: {max_samples}")
    click.echo(f"Output: {output_dir}")
    click.echo()
    
    try:
        summary = run_live_extraction_pipeline(
            output_dir=output_dir,
            api_key=api_key,
            os_filter=list(os_filter),
            min_score=min_score,
            days=days,
            max_samples=max_samples,
            min_confidence=min_confidence,
            split_by_os=not no_split,
            generate_deception=not no_deception,
        )
        
        # Print summary
        click.echo()
        click.echo("=" * 60)
        click.echo("EXTRACTION COMPLETE")
        click.echo("=" * 60)
        click.echo(f"Extraction ID: {summary['extraction_id']}")
        click.echo(f"Source: {summary.get('source', 'api')}")
        click.echo(f"Total artifacts: {summary['statistics']['total_artifacts']}")
        
        if summary['statistics']['by_os']:
            click.echo("\nBy OS:")
            for os_name, count in summary['statistics']['by_os'].items():
                click.echo(f"  {os_name}: {count}")
        
        if summary['errors'] > 0:
            click.echo(f"\nErrors: {summary['errors']}")
        
        click.echo("\nOutput files:")
        for file_type, files in summary['output_files'].items():
            for f in files:
                click.echo(f"  {f}")
        
    except Exception as e:
        raise click.ClickException(f"Extraction failed: {e}")


@cli.command("test-api")
@click.option(
    "--api-key",
    envvar="TRIAGE_API_KEY",
    help="Triage API key (or set TRIAGE_API_KEY env var).",
)
def test_api(api_key: Optional[str]) -> None:
    """
    Test connection to Triage API.
    
    Verifies that your API key is valid and the API is reachable.
    """
    from extractor.triage.client import TriageClient, TriageAPIError
    
    if not api_key:
        raise click.ClickException(
            "API key required. Set TRIAGE_API_KEY environment variable or use --api-key."
        )
    
    click.echo("Testing Triage API connection...")
    
    try:
        client = TriageClient(api_key=api_key)
        
        if client.test_connection():
            click.echo("[OK] Connection successful!")
            click.echo(f"  API endpoint: {client.base_url}")
            
            # Try to get a sample count
            samples = list(client.search("tag:android", limit=1))
            click.echo(f"  Search working: found samples")
        else:
            click.echo("[FAIL] Connection failed")
            raise click.ClickException("API connection test failed")
            
    except TriageAPIError as e:
        raise click.ClickException(f"API error: {e}")
    except Exception as e:
        raise click.ClickException(f"Error: {e}")


@cli.command("cache-stats")
def cache_stats() -> None:
    """
    Show API response cache statistics.
    
    Displays cache size, entry counts, and breakdown by type.
    """
    from extractor.triage.cache import TriageCache
    
    cache = TriageCache()
    stats = cache.get_stats()
    cache.close()
    
    if not stats.get("enabled"):
        click.echo("Cache is not enabled.")
        return
    
    click.echo("=" * 50)
    click.echo("API CACHE STATISTICS")
    click.echo("=" * 50)
    click.echo(f"Database: {stats['db_path']}")
    click.echo(f"Total entries: {stats['total_entries']}")
    click.echo(f"Total size: {stats['total_size_mb']} MB")
    click.echo(f"Expired entries: {stats['expired_entries']}")
    
    if stats.get("by_type"):
        click.echo("\nBy type:")
        for entry_type, type_stats in stats["by_type"].items():
            size_kb = type_stats["size_bytes"] / 1024
            click.echo(f"  {entry_type}: {type_stats['count']} entries ({size_kb:.1f} KB)")


@cli.command("clear-cache")
@click.option(
    "--type",
    "cache_type",
    type=click.Choice(["all", "overview", "behavioral", "kernel_logs", "search"]),
    default="all",
    help="Type of cache entries to clear (default: all).",
)
@click.confirmation_option(prompt="Are you sure you want to clear the cache?")
def clear_cache(cache_type: str) -> None:
    """
    Clear the API response cache.
    
    Use --type to clear only specific entry types.
    """
    from extractor.triage.cache import TriageCache
    
    cache = TriageCache()
    
    if cache_type == "all":
        cache.clear()
        click.echo("Cache cleared.")
    else:
        cache.clear_type(cache_type)
        click.echo(f"Cleared {cache_type} cache entries.")
    
    cache.close()


@cli.command("compare")
@click.argument("previous_file", type=click.Path(exists=True, path_type=Path))
@click.argument("current_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--output",
    "-o",
    "output_file",
    type=click.Path(path_type=Path),
    default=Path("extraction_changes.json"),
    help="Output file for change report (default: extraction_changes.json).",
)
def compare(
    previous_file: Path,
    current_file: Path,
    output_file: Path,
) -> None:
    """
    Compare two artifact files and generate a change report.
    
    Shows new, updated, and removed artifacts between extraction runs.
    
    Examples:
    
        # Compare previous and current extractions
        python -m extractor.cli compare old/artifacts.json new/artifacts.json
        
        # Write to custom output file
        python -m extractor.cli compare old.json new.json -o changes.json
    """
    from extractor.output.change_reporter import compare_and_write_report
    
    click.echo(f"Comparing {previous_file} vs {current_file}...")
    
    try:
        report = compare_and_write_report(
            previous_file=previous_file,
            current_file=current_file,
            output_file=output_file,
        )
        
        click.echo()
        click.echo("=" * 50)
        click.echo("CHANGE REPORT")
        click.echo("=" * 50)
        click.echo(f"Total changes: {report.total_changes}")
        click.echo(f"  New:       {report.new_count}")
        click.echo(f"  Updated:   {report.updated_count}")
        click.echo(f"  Removed:   {report.removed_count}")
        click.echo(f"  Unchanged: {report.unchanged_count}")
        
        if report.changes_by_os:
            click.echo("\nChanges by OS:")
            for os_name, counts in report.changes_by_os.items():
                click.echo(f"  {os_name}:")
                click.echo(f"    new={counts.get('new', 0)}, "
                          f"updated={counts.get('updated', 0)}, "
                          f"removed={counts.get('removed', 0)}")
        
        if report.new_artifacts:
            click.echo(f"\nNew artifacts ({len(report.new_artifacts)}):")
            for change in report.new_artifacts[:10]:
                click.echo(f"  + [{change.os}] {change.value[:60]}")
            if len(report.new_artifacts) > 10:
                click.echo(f"  ... and {len(report.new_artifacts) - 10} more")
        
        click.echo(f"\nReport written to: {output_file}")
        
    except Exception as e:
        raise click.ClickException(f"Compare failed: {e}")


if __name__ == "__main__":
    cli()
