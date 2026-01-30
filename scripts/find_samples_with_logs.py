#!/usr/bin/env python3
"""
Find samples that have kernel logs available.

Kernel logs contain the detailed syscall traces we need for extraction:
- Android/Linux: stahp.json
- Windows: onemon.json
- macOS: bigmac.json
"""

import os
import sys
import time
import requests

API_KEY = os.environ.get("TRIAGE_API_KEY")
BASE_URL = "https://private.tria.ge/api/v0"

headers = {"Authorization": f"Bearer {API_KEY}"}

KERNEL_LOG_FILES = {
    "android": "stahp.json",
    "linux": "stahp.json",
    "windows": "onemon.json",
    "macos": "bigmac.json",
}


def check_kernel_logs(sample_id: str, os_type: str) -> bool:
    """Check if kernel logs exist for a sample."""
    log_file = KERNEL_LOG_FILES.get(os_type)
    if not log_file:
        return False
    
    url = f"{BASE_URL}/samples/{sample_id}/behavioral1/logs/{log_file}"
    try:
        resp = requests.head(url, headers=headers, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def search_samples(os_type: str, limit: int = 20) -> list[dict]:
    """Search for samples of a given OS."""
    print(f"Searching for {os_type} samples...")
    try:
        resp = requests.get(
            f"{BASE_URL}/search",
            params={"query": f"tag:{os_type}"},
            headers=headers,
            timeout=60
        )
        if resp.status_code == 200:
            data = resp.json()
            samples = data.get("data", [])[:limit]
            return samples
        else:
            print(f"  Error: {resp.status_code}")
            return []
    except Exception as e:
        print(f"  Exception: {e}")
        return []


def find_samples_with_logs(os_type: str, max_check: int = 10) -> list[str]:
    """Find samples that have kernel logs available."""
    samples = search_samples(os_type, limit=max_check * 2)
    
    found = []
    for i, sample in enumerate(samples[:max_check]):
        sample_id = sample.get("id")
        filename = sample.get("filename", "unknown")
        
        print(f"  [{i+1}/{max_check}] Checking {sample_id} ({filename})...", end=" ")
        
        if check_kernel_logs(sample_id, os_type):
            print("HAS LOGS!")
            found.append(sample_id)
        else:
            print("no logs")
        
        time.sleep(0.3)  # Rate limit
    
    return found


def main():
    if not API_KEY:
        print("Error: TRIAGE_API_KEY not set")
        return 1
    
    print("=" * 60)
    print("Searching for samples with kernel logs...")
    print("=" * 60)
    
    results = {}
    
    for os_type in ["android", "windows"]:
        print(f"\n{os_type.upper()}:")
        found = find_samples_with_logs(os_type, max_check=15)
        results[os_type] = found
        print(f"  Found {len(found)} samples with kernel logs")
    
    print("\n" + "=" * 60)
    print("SUMMARY - Samples with kernel logs:")
    print("=" * 60)
    
    for os_type, samples in results.items():
        if samples:
            print(f"\n{os_type}:")
            for sid in samples:
                print(f"  {sid}")
    
    # Output capture commands
    print("\n" + "=" * 60)
    print("CAPTURE COMMANDS:")
    print("=" * 60)
    
    for os_type, samples in results.items():
        if samples:
            sample_args = " ".join(f"--sample-id {sid}" for sid in samples[:3])
            print(f"\npython scripts/capture_fixtures.py --os {os_type} {sample_args}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
