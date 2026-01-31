"""
Extraction pipeline.

Orchestrates the full extraction flow:
1. Load sample data (from fixtures or API)
2. Detect OS and select appropriate extractor
3. Extract artifacts
4. Aggregate (deduplicate, score)
5. Filter
6. Write outputs
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from extractor.models.artifact import Artifact, OSType
from extractor.models.sample import SampleMetadata
from extractor.models.extraction import ExtractionResult, ExtractionParameters
from extractor.extractors.base import ExtractionContext
from extractor.extractors.android import AndroidExtractor
from extractor.extractors.windows import WindowsExtractor
from extractor.extractors.linux import LinuxExtractor
from extractor.extractors.macos import MacOSExtractor
from extractor.aggregation.deduplicator import deduplicate_artifacts
from extractor.aggregation.scorer import score_artifacts
from extractor.aggregation.filter import filter_artifacts, FilterConfig
from extractor.output.json_writer import write_artifacts_json, write_per_os_json
from extractor.output.yaml_writer import write_deception_yaml

logger = logging.getLogger(__name__)


# Map OS types to extractors
EXTRACTORS = {
    OSType.ANDROID: AndroidExtractor,
    OSType.WINDOWS: WindowsExtractor,
    OSType.LINUX: LinuxExtractor,
    OSType.MACOS: MacOSExtractor,
}


def detect_os_from_overview(overview: dict[str, Any]) -> OSType | None:
    """
    Detect OS type from sample overview data.
    
    Uses the same logic as infer_os_from_sample() in client.py:
    1. Check tasks for os/platform field (most reliable)
    2. Check analysis tags
    3. Check target filename extension
    4. Check sample tags
    
    Args:
        overview: Sample overview JSON from Triage
        
    Returns:
        OSType or None if not detectable
    """
    # Use the client's inference function for consistency
    from extractor.triage.client import infer_os_from_sample
    
    os_str = infer_os_from_sample(overview)
    
    if os_str:
        # Convert string to OSType enum
        os_map = {
            "android": OSType.ANDROID,
            "windows": OSType.WINDOWS,
            "linux": OSType.LINUX,
            "macos": OSType.MACOS,
        }
        os_type = os_map.get(os_str.lower())
        if os_type:
            logger.debug(f"Detected OS from overview: {os_type.value}")
            return os_type
    
    logger.warning(f"Could not detect OS from overview")
    return None


def extract_sample(
    overview: dict[str, Any],
    behavioral_report: dict[str, Any],
    kernel_logs: list[dict[str, Any]] | None = None,
    os_type: OSType | None = None,
) -> ExtractionResult:
    """
    Extract artifacts from a single sample.
    
    Args:
        overview: Sample overview JSON
        behavioral_report: Behavioral report JSON
        kernel_logs: Optional kernel log entries
        os_type: Override OS detection (optional)
        
    Returns:
        ExtractionResult with extracted artifacts
    """
    # Parse sample metadata
    metadata = SampleMetadata.from_overview(overview)
    logger.info(f"Extracting from sample {metadata.triage.sample_id} ({metadata.filename})")
    
    # Detect OS if not provided
    if os_type is None:
        os_type = detect_os_from_overview(overview)
    
    if os_type is None:
        logger.error("Could not detect OS type")
        result = ExtractionResult()
        result.add_error(
            sample_id=metadata.triage.sample_id,
            error="Could not detect OS type from sample",
        )
        return result
    
    logger.info(f"Detected OS: {os_type.value}")
    
    # Get extractor for this OS
    extractor_class = EXTRACTORS.get(os_type)
    if extractor_class is None:
        logger.warning(f"No extractor available for {os_type.value}")
        result = ExtractionResult()
        result.add_error(
            sample_id=metadata.triage.sample_id,
            error=f"No extractor implemented for {os_type.value}",
        )
        return result
    
    # Create extraction context
    context = ExtractionContext(
        sample_metadata=metadata,
        behavioral_report=behavioral_report,
        kernel_logs=kernel_logs,
    )
    
    # Run extraction
    extractor = extractor_class()
    try:
        artifacts = extractor.extract(context)
        logger.info(f"Extracted {len(artifacts)} raw artifacts")
    except Exception as e:
        logger.error(f"Extraction failed: {e}")
        result = ExtractionResult()
        result.add_error(
            sample_id=metadata.triage.sample_id,
            error=f"Extraction error: {str(e)}",
        )
        return result
    
    # Build result
    result = ExtractionResult()
    
    for artifact in artifacts:
        result.add_artifact(artifact)
    
    return result


def aggregate_results(
    results: list[ExtractionResult],
    filter_config: FilterConfig | None = None,
) -> ExtractionResult:
    """
    Aggregate multiple extraction results.
    
    Combines artifacts from all results, deduplicates, scores, and filters.
    
    Args:
        results: List of extraction results to aggregate
        filter_config: Optional filter configuration
        
    Returns:
        Aggregated ExtractionResult
    """
    logger.info(f"Aggregating {len(results)} extraction results...")
    
    # Collect all artifacts
    all_artifacts: list[Artifact] = []
    all_errors = []
    os_targets = set()
    
    for result in results:
        all_artifacts.extend(result.get_all_artifacts())
        all_errors.extend(result.errors)
        # Track OS types from artifacts since parameters are internal
        for artifact in result.get_all_artifacts():
            os_targets.add(artifact.os)
    
    logger.info(f"Total raw artifacts: {len(all_artifacts)}")
    
    # Deduplicate
    unique_artifacts = deduplicate_artifacts(all_artifacts)
    logger.info(f"After deduplication: {len(unique_artifacts)} unique artifacts")
    
    # Score
    scored_artifacts = score_artifacts(unique_artifacts)
    
    # Filter
    if filter_config:
        filtered_artifacts = filter_artifacts(scored_artifacts, filter_config)
    else:
        filtered_artifacts = scored_artifacts
    
    logger.info(f"After filtering: {len(filtered_artifacts)} artifacts")
    
    # Build aggregated result
    aggregated = ExtractionResult()
    
    for artifact in filtered_artifacts:
        aggregated.add_artifact(artifact)
    
    for error in all_errors:
        aggregated.errors.append(error)
    
    return aggregated


def write_outputs(
    result: ExtractionResult,
    output_dir: Path | str,
    split_by_os: bool = True,
    generate_deception: bool = True,
) -> dict[str, list[Path]]:
    """
    Write extraction results to output files.
    
    Args:
        result: Extraction result to write
        output_dir: Directory for output files
        split_by_os: Write per-OS JSON files
        generate_deception: Generate deception YAML configs
        
    Returns:
        Dictionary of output type to list of written files
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    written: dict[str, list[Path]] = {
        "json": [],
        "yaml": [],
    }
    
    artifacts = result.get_all_artifacts()
    logger.info(f"Writing {len(artifacts)} artifacts to {output_dir}")
    
    # Main artifacts.json
    main_json = write_artifacts_json(artifacts, output_dir / "artifacts.json")
    written["json"].append(main_json)
    
    # Per-OS JSON files
    if split_by_os:
        per_os_files = write_per_os_json(artifacts, output_dir)
        written["json"].extend(per_os_files)
    
    # Deception YAML configs
    if generate_deception:
        yaml_files = write_deception_yaml(artifacts, output_dir)
        written["yaml"].extend(yaml_files)
    
    # Log summary
    logger.info(f"Wrote {len(written['json'])} JSON files, {len(written['yaml'])} YAML files")
    
    return written


# =============================================================================
# Fixture-based extraction (for testing and offline use)
# =============================================================================

def extract_from_fixtures(
    fixtures_dir: Path | str | None = None,
    os_filter: list[str] | None = None,
    filter_config: FilterConfig | None = None,
) -> ExtractionResult:
    """
    Extract artifacts from local fixture files.
    
    This is useful for testing and offline development.
    
    Args:
        fixtures_dir: Path to fixtures directory (default: tests/fixtures)
        os_filter: List of OS types to include (default: all)
        filter_config: Optional filter configuration
        
    Returns:
        Aggregated ExtractionResult
    """
    from extractor.testing.fixtures import (
        discover_all_samples,
        load_overview,
        load_behavioral_report,
        load_kernel_logs,
        has_kernel_logs,
    )
    
    logger.info("Extracting from local fixtures...")
    
    # Discover available samples
    samples = discover_all_samples()
    
    if not samples:
        logger.warning("No fixtures found")
        return ExtractionResult()
    
    # Filter by OS if requested
    if os_filter:
        os_filter_lower = [o.lower() for o in os_filter]
        samples = {os: ids for os, ids in samples.items() if os in os_filter_lower}
    
    logger.info(f"Found fixtures: {samples}")
    
    # Extract from each sample
    results: list[ExtractionResult] = []
    
    for os_name, sample_ids in samples.items():
        for sample_id in sample_ids:
            logger.info(f"Processing {os_name}/{sample_id}...")
            
            try:
                # Load data
                overview = load_overview(os_name, sample_id)
                behavioral = load_behavioral_report(os_name, sample_id, "behavioral1")
                
                # Load kernel logs if available
                kernel_logs = None
                if has_kernel_logs(os_name, sample_id, "behavioral1"):
                    kernel_logs = load_kernel_logs(os_name, sample_id, "behavioral1")
                
                # Extract
                result = extract_sample(
                    overview=overview,
                    behavioral_report=behavioral,
                    kernel_logs=kernel_logs,
                )
                results.append(result)
                
            except Exception as e:
                logger.error(f"Failed to process {os_name}/{sample_id}: {e}")
                # Create error result
                error_result = ExtractionResult()
                error_result.add_error(
                    sample_id=sample_id,
                    error=f"Fixture error: {str(e)}",
                )
                results.append(error_result)
    
    # Aggregate all results
    return aggregate_results(results, filter_config)


def run_extraction_pipeline(
    output_dir: Path | str,
    os_filter: list[str] | None = None,
    min_confidence: float = 0.0,
    min_sample_count: int = 1,
    split_by_os: bool = True,
    generate_deception: bool = True,
) -> dict[str, Any]:
    """
    Run the full extraction pipeline on local fixtures.
    
    Args:
        output_dir: Directory for output files
        os_filter: List of OS types to include
        min_confidence: Minimum confidence threshold
        min_sample_count: Minimum sample count threshold
        split_by_os: Write per-OS JSON files
        generate_deception: Generate deception YAML configs
        
    Returns:
        Summary of extraction results
    """
    logger.info("Starting extraction pipeline...")
    
    # Configure filtering
    filter_config = FilterConfig(
        min_confidence=min_confidence,
        min_sample_count=min_sample_count,
    )
    
    # Extract from fixtures
    result = extract_from_fixtures(
        os_filter=os_filter,
        filter_config=filter_config,
    )
    
    # Write outputs
    written = write_outputs(
        result=result,
        output_dir=output_dir,
        split_by_os=split_by_os,
        generate_deception=generate_deception,
    )
    
    # Build summary
    summary = {
        "extraction_id": result.extraction_id,
        "extracted_at": result.extracted_at.isoformat(),
        "statistics": {
            "total_artifacts": result.statistics.total_artifacts,
            "by_os": dict(result.statistics.by_os),  # Already string keys
        },
        "errors": len(result.errors),
        "output_files": {
            "json": [str(p) for p in written["json"]],
            "yaml": [str(p) for p in written["yaml"]],
        },
    }
    
    logger.info(f"Pipeline complete: {result.statistics.total_artifacts} artifacts extracted")
    
    return summary


# =============================================================================
# Live API extraction
# =============================================================================

def extract_from_api(
    api_key: str | None = None,
    os_filter: list[str] | None = None,
    min_score: int = 5,
    days: int = 7,
    max_samples: int = 20,
    filter_config: FilterConfig | None = None,
    use_private_cloud: bool = True,
) -> ExtractionResult:
    """
    Extract artifacts from live Triage API.
    
    Searches for samples with tag:evasion and filters by inferred OS.
    OS is inferred from file extension and platform fields since there's
    no OS filter in the Triage search API.
    
    Args:
        api_key: Triage API key (or use TRIAGE_API_KEY env var)
        os_filter: List of OS types to include (default: all)
                   Samples are filtered by inferred OS after search.
        min_score: Minimum sample score to include
        days: Look back period in days (currently unused - for future date filtering)
        max_samples: Maximum samples to process total
        filter_config: Optional filter configuration
        use_private_cloud: If True, use private.tria.ge; else use api.tria.ge
        
    Returns:
        Aggregated ExtractionResult
    """
    from extractor.triage.client import TriageClient, TriageAPIError
    
    logger.info("Extracting from live Triage API (searching for tag:evasion)...")
    
    # Initialize client with configurable cloud setting
    try:
        client = TriageClient(api_key=api_key, use_private_cloud=use_private_cloud)
    except ValueError as e:
        logger.error(f"Client initialization failed: {e}")
        result = ExtractionResult()
        result.add_error(sample_id="", error=str(e))
        return result
    
    # Test connection
    if not client.test_connection():
        result = ExtractionResult()
        result.add_error(sample_id="", error="Failed to connect to Triage API")
        return result
    
    results: list[ExtractionResult] = []
    
    # Search for evasion samples with optional OS filter
    # The new search_evasion_samples method handles OS filtering internally
    logger.info(f"Searching for evasion samples (OS filter: {os_filter}, limit: {max_samples})")
    
    try:
        # Search with OS filter - samples will have 'inferred_os' field
        samples = list(client.search_evasion_samples(
            os_filter=os_filter,
            limit=max_samples,
            fetch_overview=True,  # Get overview for accurate OS detection
        ))
    except TriageAPIError as e:
        logger.error(f"Search failed: {e}")
        result = ExtractionResult()
        result.add_error(sample_id="", error=f"Search failed: {e}")
        return result
    
    logger.info(f"Found {len(samples)} evasion samples matching filter")
    
    # Process each sample
    processed = 0
    for sample in samples:
        sample_id = sample.get("id")
        inferred_os = sample.get("inferred_os")
        
        if not sample_id:
            continue
        
        logger.info(f"Processing sample {sample_id} (inferred OS: {inferred_os})...")
        
        try:
            # Fetch full sample data
            data = client.fetch_sample_data(sample_id)
            
            if not data.get("overview"):
                logger.warning(f"No overview for {sample_id}")
                continue
            
            # Check score from overview
            overview = data["overview"]
            score = overview.get("analysis", {}).get("score", 0)
            if score is None:
                score = overview.get("sample", {}).get("score", 0)
            
            if score is not None and score < min_score:
                logger.debug(f"Skipping {sample_id}: score {score} < {min_score}")
                continue
            
            if not data.get("behavioral_report"):
                logger.warning(f"No behavioral report for {sample_id}")
                continue
            
            # Extract artifacts
            result = extract_sample(
                overview=data["overview"],
                behavioral_report=data["behavioral_report"],
                kernel_logs=data.get("kernel_logs"),
            )
            results.append(result)
            processed += 1
            
            logger.debug(f"Extracted {len(result.get_all_artifacts())} artifacts from {sample_id}")
            
        except TriageAPIError as e:
            logger.error(f"Failed to fetch {sample_id}: {e}")
            error_result = ExtractionResult()
            error_result.add_error(sample_id=sample_id, error=str(e))
            results.append(error_result)
        
        except Exception as e:
            logger.error(f"Failed to process {sample_id}: {e}")
            error_result = ExtractionResult()
            error_result.add_error(sample_id=sample_id, error=f"Processing error: {e}")
            results.append(error_result)
    
    logger.info(f"Processed {processed} samples successfully")
    
    # Aggregate all results
    return aggregate_results(results, filter_config)


def run_live_extraction_pipeline(
    output_dir: Path | str,
    api_key: str | None = None,
    os_filter: list[str] | None = None,
    min_score: int = 5,
    days: int = 7,
    max_samples: int = 20,
    min_confidence: float = 0.0,
    min_sample_count: int = 1,
    split_by_os: bool = True,
    generate_deception: bool = True,
    use_private_cloud: bool = True,
) -> dict[str, Any]:
    """
    Run the full extraction pipeline with live API data.
    
    Searches for samples with tag:evasion and extracts anti-analysis artifacts.
    OS is inferred from file extensions and platform fields.
    
    Args:
        output_dir: Directory for output files
        api_key: Triage API key
        os_filter: List of OS types to include (samples filtered by inferred OS)
        min_score: Minimum sample score
        days: Look back period in days (for future date filtering)
        max_samples: Maximum samples to process
        min_confidence: Minimum confidence threshold
        min_sample_count: Minimum sample count threshold
        split_by_os: Write per-OS JSON files
        generate_deception: Generate deception YAML configs
        use_private_cloud: If True, use private.tria.ge; else use api.tria.ge
        
    Returns:
        Summary of extraction results
    """
    logger.info("Starting live extraction pipeline (searching for tag:evasion)...")
    
    # Configure filtering
    filter_config = FilterConfig(
        min_confidence=min_confidence,
        min_sample_count=min_sample_count,
    )
    
    # Extract from API
    result = extract_from_api(
        api_key=api_key,
        os_filter=os_filter,
        min_score=min_score,
        days=days,
        max_samples=max_samples,
        filter_config=filter_config,
        use_private_cloud=use_private_cloud,
    )
    
    # Write outputs
    written = write_outputs(
        result=result,
        output_dir=output_dir,
        split_by_os=split_by_os,
        generate_deception=generate_deception,
    )
    
    # Build summary
    summary = {
        "extraction_id": result.extraction_id,
        "extracted_at": result.extracted_at.isoformat(),
        "source": "live_api",
        "statistics": {
            "total_artifacts": result.statistics.total_artifacts,
            "by_os": dict(result.statistics.by_os),
        },
        "errors": len(result.errors),
        "output_files": {
            "json": [str(p) for p in written["json"]],
            "yaml": [str(p) for p in written["yaml"]],
        },
    }
    
    logger.info(f"Live pipeline complete: {result.statistics.total_artifacts} artifacts extracted")
    
    return summary
