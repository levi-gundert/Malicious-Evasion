"""Summarize controlled, paired observations without running samples."""

from collections import Counter
import re


def summarize_trials(trials):
    outcomes = Counter()
    samples, families, trial_ids = set(), set(), set()
    allowed = {"harmful", "terminated", "delayed", "no_activity", "failed"}
    for trial in trials:
        if not re.fullmatch(r"[0-9a-fA-F]{64}", trial["sample_sha256"]):
            raise ValueError("A complete SHA256 is required")
        if type(trial["repeat"]) is not int or trial["repeat"] < 1:
            raise ValueError("Repeat must be a positive integer")
        identity = (trial["sample_sha256"], trial["recipe"], trial["repeat"])
        if identity in trial_ids:
            raise ValueError("Duplicate paired trial")
        trial_ids.add(identity)
        if trial["baseline_environment"] != trial["decoy_environment"]:
            raise ValueError(
                "Paired environments must be identical except for the declared recipe"
            )
        if (
            trial["baseline_seconds"] != trial["decoy_seconds"]
            or trial["baseline_seconds"] <= 0
        ):
            raise ValueError("Paired observation windows must match and be positive")
        baseline, decoy = trial["baseline_outcome"], trial["decoy_outcome"]
        if baseline not in allowed or decoy not in allowed:
            raise ValueError("Unknown outcome")
        samples.add(trial["sample_sha256"])
        families.add(trial["family"])
        if baseline != "harmful" or decoy == "failed":
            outcomes["inconclusive"] += 1
        elif decoy == "terminated":
            outcomes["observed_termination"] += 1
        elif decoy == "harmful":
            outcomes["harmful_behavior_continued"] += 1
        else:
            outcomes["delay_or_no_activity"] += 1
    return {
        "paired_trials": len(trial_ids),
        "unique_samples": len(samples),
        "families": len(families),
        "outcomes": dict(outcomes),
        "interpretation": "Observed outcomes in the supplied experiment only; no protection-rate or general efficacy claim. Independent review and held-out validation are required.",
    }
