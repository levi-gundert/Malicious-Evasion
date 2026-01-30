# Triage API Reference

> Last updated: 2026-01-28
> API Version: v0 (stable)

## Overview

Hatching Triage is a cloud-based malware analysis sandbox that provides automated behavioral analysis. This document covers the API endpoints and data structures needed for the Evasion Artifact Extractor.

---

## Base URLs

| Environment | Base URL |
|-------------|----------|
| Public Cloud | `https://api.tria.ge/v0/` |
| Public Cloud (Web) | `https://tria.ge/api/v0/` |
| Private Cloud | `https://private.tria.ge/api/v0/` |
| RecordedFuture Sandbox | `https://sandbox.recordedfuture.com/api/v0/` |
| RecordedFuture US | `https://us-sandbox.recordedfuture.com/api/v0/` |

**Note**: The Python client defaults to `https://api.tria.ge` (without `/v0/` suffix - it's added by the client).

---

## Authentication

All API requests require a bearer token in the `Authorization` header:

```
Authorization: Bearer <YOUR_API_KEY>
```

API keys are obtained from the Account page on Triage. A **Researcher account** is required for API access.

---

## API Conventions

### Response Formats

**Success (HTTP 200):**
- Single objects return as root elements
- Arrays are wrapped in a `"data"` field
- Empty responses return as empty objects `{}`

**Error Response Structure:**
```json
{
  "error": "ERROR_CODE",
  "message": "Human-readable explanation"
}
```

### Error Codes

| HTTP Code | Error Code | Description |
|-----------|------------|-------------|
| 400 | `BAD_REQUEST` | Request decoding failure |
| 400 | `INVALID` | Invalid field values |
| 401 | `UNAUTHORIZED` | Missing/invalid credentials |
| 404 | `NOT_FOUND` | Resource doesn't exist |
| 404 | `REPORT_NOT_AVAILABLE` | Report not yet generated |
| 405 | `METHOD_NOT_ALLOWED` | Unsupported HTTP method |
| 429 | (rate limited) | Too many requests |
| 500 | `INTERNAL` | Server error (may retry) |

### Pagination

Collection endpoints support:
- `limit`: Max items per response (default: 50, max: 200)
- `offset`: Opaque string for pagination position

Response includes `next` field with subsequent page offset when applicable.

### Timestamps

All timestamps use **UTC in RFC3339 format**: `2019-04-05T14:28:15Z`

---

## Core Endpoints

### Search Samples

```
GET /search?query={query}
```

Search for samples using query syntax.

**Query Syntax:**

| Operator | Description | Example |
|----------|-------------|---------|
| `tag:` | OS/behavior tag | `tag:android`, `tag:windows` |
| `family:` | Malware family | `family:emotet` |
| `score:` | Threat score | `score:>=7` |
| `from:` / `to:` | Date range | `from:2026-01-01` |
| `md5:`, `sha256:` | Hash lookup | `sha256:abc123...` |
| `AND`, `OR`, `NOT` | Boolean operators | `tag:windows AND score:>=7` |

**Example Query for Extraction:**
```
tag:android AND score:>=7 AND from:2026-01-21
```

**Response:**
```json
{
  "data": [
    {
      "id": "sample-id-here",
      "status": "reported",
      "kind": "file",
      "filename": "malware.apk",
      "private": false,
      "submitted": "2026-01-25T10:30:00Z"
    }
  ],
  "next": "offset-token"
}
```

### Get Sample Metadata

```
GET /samples/{sampleID}
```

Retrieve basic sample information.

**Response:**
```json
{
  "id": "sample-id",
  "status": "reported",
  "kind": "file",
  "filename": "sample.exe",
  "private": false,
  "submitted": "2026-01-25T10:30:00Z",
  "completed": "2026-01-25T10:35:00Z"
}
```

**Sample Status Values:**
- `pending` - Queued for analysis
- `static_analysis` - Static analysis in progress
- `scheduled` - Scheduled for dynamic analysis
- `running` - Executing in sandbox
- `processing` - Generating reports
- `reported` - Analysis complete
- `failed` - Analysis failed

### Get Overview Report

```
GET /samples/{sampleID}/overview.json
```

Returns comprehensive sample analysis summary.

**Response Schema:**
```json
{
  "version": "0.3",
  "sample": {
    "id": "sample-id",
    "target": "malware.apk",
    "size": 123456,
    "md5": "...",
    "sha1": "...",
    "sha256": "...",
    "sha512": "...",
    "submitted": "2026-01-25T10:30:00Z",
    "completed": "2026-01-25T10:35:00Z"
  },
  "tasks": [
    {
      "task": "behavioral1",
      "target": "malware.apk",
      "platform": "android",
      "score": 10,
      "tags": ["android", "trojan", "banker"],
      "ttps": ["T1422", "T1426"]
    }
  ],
  "analysis": {
    "score": 10,
    "family": ["anatsa"],
    "tags": ["android", "trojan", "banker"]
  },
  "targets": [...],
  "signatures": [...],
  "extracted": [...],
  "iocs": {
    "urls": [...],
    "domains": [...],
    "ips": [...]
  }
}
```

### Get Behavioral Report (Dynamic Report)

```
GET /samples/{sampleID}/{taskID}/report_triage.json
```

Where `taskID` is typically `behavioral1` or `behavioral2`.

**Response Schema:**
```json
{
  "version": "0.3",
  "sample": {...},
  "task": {
    "task": "behavioral1",
    "target": "malware.apk",
    "backend": "android",
    "resource": "android-x86_64"
  },
  "analysis": {
    "reported": "2026-01-25T10:35:00Z",
    "score": 10,
    "tags": ["android", "trojan"]
  },
  "processes": [...],
  "signatures": [...],
  "network": {...},
  "dumped": [...],
  "extracted": [...]
}
```

### Get Kernel Logs

Platform-specific kernel monitoring logs provide detailed syscall and file operation data.

**Windows:**
```
GET /samples/{sampleID}/{taskID}/logs/onemon.json
```

**macOS:**
```
GET /samples/{sampleID}/{taskID}/logs/bigmac.json
```

**Linux/Android:**
```
GET /samples/{sampleID}/{taskID}/logs/stahp.json
```

---

## Behavioral Data Structures

### Process Information

Found in `report_triage.json` under `processes` array:

```json
{
  "procid": 1,
  "procid_parent": 0,
  "pid": 1234,
  "ppid": 1,
  "cmd": "/system/bin/app_process",
  "image": "/system/bin/app_process64",
  "orig": true,
  "started": 1000,
  "terminated": 5000
}
```

### Network Activity

Found in `report_triage.json` under `network`:

```json
{
  "flows": [
    {
      "id": 1,
      "src": "10.0.0.2:45678",
      "dst": "192.168.1.1:80",
      "proto": "tcp",
      "pid": 1234,
      "procid": 1,
      "first_seen": 1000,
      "last_seen": 2000,
      "rx_bytes": 1024,
      "tx_bytes": 512
    }
  ],
  "requests": [...]
}
```

### Dumped Files

Found in `report_triage.json` under `dumped`:

```json
{
  "at": 1500,
  "pid": 1234,
  "procid": 1,
  "path": "/data/local/tmp/payload.dex",
  "name": "dump-001",
  "kind": "martian",
  "md5": "...",
  "sha256": "..."
}
```

### Signatures

Behavioral detections with MITRE ATT&CK mapping:

```json
{
  "name": "anti_vm_file_check",
  "label": "Checks for emulator files",
  "score": 8,
  "ttp": ["T1497.001"],
  "tags": ["evasion", "anti-vm"],
  "indicators": [
    {
      "description": "Checks /system/bin/qemu-props"
    }
  ]
}
```

---

## Platform-Specific Kernel Log Structures

### Onemon (Windows) Event Types

The `onemon.json` file contains detailed Windows system call monitoring:

**File Operations:**
```json
{
  "kind": "file_open",
  "pid": 1234,
  "path": "C:\\Windows\\System32\\drivers\\vmci.sys",
  "ts": 1500,
  "ret": 0
}
```

**Registry Operations:**
```json
{
  "kind": "reg_open",
  "pid": 1234,
  "key": "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools",
  "ts": 1600,
  "ret": -1
}
```

**Process Operations:**
```json
{
  "kind": "proc_enum",
  "pid": 1234,
  "ts": 1700
}
```

### Bigmac (macOS) Event Types

Similar structure with syscall tracking:

```json
{
  "kind": "SyscallSI",
  "args": ["/Library/Application Support/VMware Tools"],
  "pid": 1234,
  "ret": -1,
  "ts": 1500
}
```

### Stahp (Linux/Android) Event Types

**File Access:**
```json
{
  "kind": "file_stat",
  "pid": 1234,
  "path": "/system/bin/qemu-props",
  "ts": 1500,
  "ret": -1
}
```

**Property Read (Android):**
```json
{
  "kind": "prop_get",
  "pid": 1234,
  "name": "ro.kernel.qemu",
  "value": "1",
  "ts": 1600
}
```

---

## Rate Limiting

### Recommendations

- **Requests per minute**: ~60 (adjust based on subscription tier)
- **Retry on 429**: Exponential backoff starting at 30 seconds
- **Max retries**: 5 attempts

### Implementation

```python
# Token bucket rate limiter
bucket_size = 60
refill_rate = 1  # token per second

# On 429 response
initial_delay = 30
max_delay = 300
retry_count = 0

while retry_count < max_retries:
    delay = min(initial_delay * (2 ** retry_count), max_delay)
    time.sleep(delay)
    retry_count += 1
```

---

## Caching Strategy

### Recommended TTLs

| Resource | TTL | Reason |
|----------|-----|--------|
| Sample metadata | 7 days | Rarely changes after submission |
| Overview report | 7 days | Immutable once generated |
| Behavioral report | 30 days | Immutable once generated |
| Search results | 1 hour | New samples may appear |

### Cache Key Format

```
triage:{endpoint}:{sample_id}:{task_id}
```

---

## Python Client Usage

### Installation

```bash
pip install hatching-triage
```

### Basic Usage

```python
from triage import Client

# Initialize client
client = Client("your-api-key")
# Or for custom URL:
client = Client("your-api-key", root_url="https://api.tria.ge")

# Search for samples
results = client.search("tag:android AND score:>=7")

# Get sample details
sample = client.sample_by_id("sample-id")

# Get overview report
overview = client.overview_report("sample-id")

# Get behavioral report
behavioral = client.task_report("sample-id", "behavioral1")
```

### Key Methods

| Method | Description |
|--------|-------------|
| `search(query)` | Search samples with pagination |
| `sample_by_id(id)` | Get sample metadata |
| `overview_report(id)` | Get overview report JSON |
| `task_report(id, task)` | Get specific task report |
| `static_report(id)` | Get static analysis report |
| `kernel_report(id, task)` | Get kernel monitoring logs |

---

## API Submission Limits

| Limit | Value |
|-------|-------|
| Max runtime (API) | 1 hour (3600 seconds) |
| Max runtime (UI) | 15-30 minutes |
| Max file size | Varies by subscription |

---

## Sources

- [Triage Documentation](https://tria.ge/docs/)
- [Triage Cloud API - Samples](https://tria.ge/docs/cloud-api/samples/)
- [Triage Cloud API - Conventions](https://tria.ge/docs/cloud-api/conventions/)
- [Triage Cloud API - Dynamic Report](https://tria.ge/docs/cloud-api/dynamic-report/)
- [Triage Cloud API - Overview Report](https://tria.ge/docs/cloud-api/overview-report/)
- [GitHub - hatching/triage](https://github.com/hatching/triage)
- [Hatching Blog - Dropped Files](https://hatching.io/blog/dropped-files/)
- [Hatching Blog - Triage for macOS](https://hatching.io/blog/triage-for-macos/)
