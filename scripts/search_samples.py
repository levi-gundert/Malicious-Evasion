#!/usr/bin/env python3
"""Quick script to search for samples on Triage."""

import os
import requests

API_KEY = os.environ.get("TRIAGE_API_KEY")
BASE_URL = "https://private.tria.ge/api/v0"

headers = {"Authorization": f"Bearer {API_KEY}"}

def search(query: str, limit: int = 3):
    """Search for samples."""
    print(f"Searching: {query}")
    resp = requests.get(
        f"{BASE_URL}/search",
        params={"query": query},
        headers=headers,
        timeout=30
    )
    if resp.status_code == 200:
        data = resp.json()
        samples = data.get("data", [])[:limit]
        total = len(data.get("data", []))
        print(f"Found {total} total, showing {len(samples)}:")
        for s in samples:
            sample_id = s.get("id", "unknown")
            filename = s.get("filename", "unknown")
            print(f"  - {sample_id} ({filename})")
        return [s.get("id") for s in samples]
    else:
        print(f"Error: {resp.status_code} - {resp.text}")
        return []

if __name__ == "__main__":
    print("=" * 50)
    # Use simpler queries for private cloud
    android_samples = search("tag:android", limit=2)
    print()
    windows_samples = search("tag:windows", limit=2)
    print("=" * 50)
    
    print("\nSample IDs to capture:")
    print(f"Android: {android_samples}")
    print(f"Windows: {windows_samples}")
