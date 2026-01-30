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
    
    Args:
        overview: Sample overview JSON from Triage
        
    Returns:
        OSType or None if not detectable
    """
    # Check analysis tags first (Triage private cloud format)
    analysis = overview.get("analysis", {})
    analysis_tags = analysis.get("tags", [])
    
    for tag in analysis_tags:
        tag_lower = tag.lower()
        if "android" in tag_lower:
            return OSType.ANDROID
        if "windows" in tag_lower:
            return OSType.WINDOWS
        if "linux" in tag_lower:
            return OSType.LINUX
        if "macos" in tag_lower:
            return OSType.MACOS
    
    # Check targets for platform info
    targets = overview.get("targets", [])
    for target in targets:
        platform = target.get("platform", "").lower()
        
        if "android" in platform:
            return OSType.ANDROID
        if "windows" in platform:
            return OSType.WINDOWS
        if "linux" in platform:
            return OSType.LINUX
        if "macos" in platform or "darwin" in platform:
            return OSType.MACOS
    
    # Check sample tags and filename
    sample = overview.get("sample", {})
    tags = sample.get("tags", [])
    
    for tag in tags:
        tag_lower = tag.lower()
        if "android" in tag_lower or "apk" in tag_lower:
            return OSType.ANDROID
        if "windows" in tag_lower or "exe" in tag_lower or "dll" in tag_lower:
            return OSType.WINDOWS
        if "linux" in tag_lower or "elf" in tag_lower:
            return OSType.LINUX
        if "macos" in tag_lower or "mach-o" in tag_lower:
            return OSType.MACOS
    
    # Check filename extension
    filename = sample.get("name", "") or sample.get("target", "")
    if filename.endswith(".apk"):
        return OSType.ANDROID
    if filename.endswith((".exe", ".dll", ".msi")):
        return OSType.WINDOWS
    if filename.endswith((".dmg", ".app")):
        return OSType.MACOS
    
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
            "by_os": {os.value: count for os, count in result.statistics.by_os.items()},
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
) -> ExtractionResult:
    """
    Extract artifacts from live Triage API.
    
    Args:
        api_key: Triage API key (or use TRIAGE_API_KEY env var)
        os_filter: List of OS types to search (default: android, windows)
        min_score: Minimum sample score to include
        days: Look back period in days
        max_samples: Maximum samples per OS
        filter_config: Optional filter configuration
        
    Returns:
        Aggregated ExtractionResult
    """
    from extractor.triage.client import TriageClient, TriageAPIError
    
    logger.info("Extracting from live Triage API...")
    
    # Initialize client
    try:
        client = TriageClient(api_key=api_key)
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
    
    # Default OS targets
    if os_filter is None:
        os_filter = ["android", "windows"]
    
    results: list[ExtractionResult] = []
    
    for os_type in os_filter:
        logger.info(f"Searching for {os_type} samples...")
        
        try:
            samples = list(client.search_evasion_samples(
                os_type=os_type,
                min_score=min_score,
                days=days,
                limit=max_samples,
            ))
        except TriageAPIError as e:
            logger.error(f"Search failed for {os_type}: {e}")
            continue
        
        logger.info(f"Found {len(samples)} {os_type} samples from search")
        
        processed = 0
        for sample in samples:
            sample_id = sample.get("id")
            if not sample_id:
                continue
            
            logger.info(f"Processing {os_type}/{sample_id}...")
            
            try:
                # Fetch full sample data
                data = client.fetch_sample_data(sample_id)
                
                if not data.get("overview"):
                    logger.warning(f"No overview for {sample_id}")
                    continue
                
                # Check score from overview (not available in search results)
                overview = data["overview"]
                score = overview.get("analysis", {}).get("score", 0)
                if score is None:
                    score = overview.get("sample", {}).get("score", 0)
                
                if score < min_score:
                    logger.debug(f"Skipping {sample_id}: score {score} < {min_score}")
                    continue
                
                if not data.get("behavioral_report"):
                    logger.warning(f"No behavioral report for {sample_id}")
                    continue
                
                # Extract
                result = extract_sample(
                    overview=data["overview"],
                    behavioral_report=data["behavioral_report"],
                    kernel_logs=data.get("kernel_logs"),
                )
                results.append(result)
                processed += 1
                
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
) -> dict[str, Any]:
    """
    Run the full extraction pipeline with live API data.
    
    Args:
        output_dir: Directory for output files
        api_key: Triage API key
        os_filter: List of OS types to include
        min_score: Minimum sample score
        days: Look back period in days
        max_samples: Maximum samples per OS
        min_confidence: Minimum confidence threshold
        min_sample_count: Minimum sample count threshold
        split_by_os: Write per-OS JSON files
        generate_deception: Generate deception YAML configs
        
    Returns:
        Summary of extraction results
    """
    logger.info("Starting live extraction pipeline...")
    
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
