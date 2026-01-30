# Behavioral Data Mapping

> Maps Triage API behavioral data to extractor requirements
> Last updated: 2026-01-28

## Overview

This document maps the behavioral data available from Triage API responses to the artifact extraction requirements defined in the specification.

---

## Data Sources

The extractor needs to pull behavioral data from multiple sources:

| Source | Endpoint | Contents |
|--------|----------|----------|
| Overview Report | `/samples/{id}/overview.json` | Sample metadata, tags, scores, families |
| Behavioral Report | `/samples/{id}/behavioral1/report_triage.json` | Processes, network, signatures, extracted data |
| Kernel Logs | `/samples/{id}/{task}/logs/{platform}.json` | Detailed syscall/file/registry operations |

### Kernel Log Files by Platform

| Platform | Log File | Description |
|----------|----------|-------------|
| Windows | `onemon.json` | Windows kernel driver monitoring |
| macOS | `bigmac.json` | macOS kernel agent monitoring |
| Linux | `stahp.json` | Linux kernel monitoring |
| Android | `stahp.json` | Android kernel monitoring |

---

## Android Extraction Mapping

### File Existence Checks

**Spec Field:** `behavioral.filesystem`

**Actual Source:** Kernel logs (`stahp.json`) or signatures/indicators in `report_triage.json`

**Event Types to Parse:**
```json
// From stahp.json kernel log
{
  "kind": "file_stat",   // or "file_open", "file_access"
  "path": "/system/bin/qemu-props",
  "pid": 1234,
  "ret": -1,             // -1 = not found, 0 = found
  "ts": 1500
}
```

**Operations to Include:**
- `file_stat`
- `file_access`
- `file_open`
- `file_exists`

### System Property Checks

**Spec Field:** `behavioral.properties_read`

**Actual Source:** Kernel logs (`stahp.json`)

**Event Type:**
```json
{
  "kind": "prop_get",
  "name": "ro.kernel.qemu",
  "value": "1",
  "pid": 1234,
  "ts": 1600
}
```

### Package Queries

**Spec Field:** `behavioral.package_queries`

**Actual Source:** Kernel logs or signatures in behavioral report

**Event Type:**
```json
{
  "kind": "pkg_query",
  "package": "de.robv.android.xposed.installer",
  "installed": false,
  "pid": 1234,
  "ts": 1700
}
```

**Alternative - from signatures:**
```json
{
  "name": "android_package_check",
  "indicators": [
    {"ioc": "de.robv.android.xposed.installer", "description": "Checks for Xposed"}
  ]
}
```

### Network Port Probes

**Spec Field:** `behavioral.network`

**Actual Source:** `report_triage.json` → `network.flows` array

```json
{
  "flows": [
    {
      "src": "10.0.0.2:45678",
      "dst": "127.0.0.1:27042",
      "proto": "tcp",
      "pid": 1234,
      "status": "refused"  // or "timeout"
    }
  ]
}
```

**Filter Criteria:**
- `dst` contains `127.0.0.1` or `localhost`
- `status` is `refused` or `timeout`

---

## Windows Extraction Mapping

### File Existence Checks

**Spec Field:** `behavioral.filesystem`

**Actual Source:** Kernel logs (`onemon.json`)

**Event Types:**
```json
{
  "kind": "file_open",
  "path": "C:\\Windows\\System32\\drivers\\vmci.sys",
  "pid": 1234,
  "ret": 0,
  "ts": 1500
}
```

### Registry Checks

**Spec Field:** `behavioral.registry`

**Actual Source:** Kernel logs (`onemon.json`)

**Event Types:**
```json
// Key existence check
{
  "kind": "reg_open",
  "key": "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools",
  "pid": 1234,
  "ret": -1,
  "ts": 1600
}

// Value query
{
  "kind": "reg_query",
  "key": "HKLM\\HARDWARE\\DESCRIPTION\\System",
  "value": "SystemBiosVersion",
  "data": "VBOX - 1",
  "pid": 1234,
  "ts": 1650
}
```

### Process Enumeration

**Spec Field:** `behavioral.processes`

**Actual Source:**
1. `report_triage.json` → `processes` array (processes that ran)
2. Kernel logs for process enumeration syscalls

**From report_triage.json:**
```json
{
  "processes": [
    {
      "procid": 1,
      "pid": 1234,
      "ppid": 1,
      "cmd": "malware.exe",
      "image": "C:\\Users\\user\\malware.exe"
    }
  ]
}
```

**From kernel logs (enumeration attempts):**
```json
{
  "kind": "proc_enum",
  "pid": 1234,
  "ts": 1700
}
```

**Note:** Process enumeration detection often comes from signatures:
```json
{
  "name": "process_enumeration",
  "indicators": [
    {"ioc": "vmtoolsd.exe", "description": "Looks for VMware Tools"}
  ]
}
```

### WMI Queries

**Spec Field:** `behavioral.wmi`

**Actual Source:** Signatures or kernel logs

**From signatures:**
```json
{
  "name": "wmi_vm_detection",
  "indicators": [
    {
      "ioc": "SELECT * FROM Win32_ComputerSystem",
      "description": "WMI query for VM detection"
    }
  ]
}
```

### Mutex Checks

**Spec Field:** `behavioral.mutexes`

**Actual Source:** Kernel logs (`onemon.json`)

```json
{
  "kind": "mutex_open",
  "name": "CuckooPipe",
  "pid": 1234,
  "ret": 0,
  "ts": 1800
}
```

---

## Linux Extraction Mapping

### File Existence Checks

**Spec Field:** `behavioral.filesystem`

**Actual Source:** Kernel logs (`stahp.json`)

```json
{
  "kind": "file_stat",
  "path": "/.dockerenv",
  "pid": 1234,
  "ret": 0,
  "ts": 1500
}
```

### Process Checks

**Spec Field:** `behavioral.processes`

**Actual Source:** `report_triage.json` → `processes` or kernel logs

```json
{
  "kind": "proc_read",
  "path": "/proc/self/status",
  "pid": 1234,
  "ts": 1600
}
```

### Environment Variables

**Spec Field:** `behavioral.environment`

**Actual Source:** Kernel logs

```json
{
  "kind": "env_get",
  "name": "CUCKOO",
  "value": "1",
  "pid": 1234,
  "ts": 1700
}
```

---

## macOS Extraction Mapping

### File Existence Checks

**Spec Field:** `behavioral.filesystem`

**Actual Source:** Kernel logs (`bigmac.json`)

```json
{
  "kind": "SyscallSI",
  "args": ["/Library/Application Support/VMware Tools"],
  "pid": 1234,
  "ret": -1,
  "ts": 1500
}
```

### System Profiler / Command Checks

**Spec Field:** `behavioral.commands`

**Actual Source:** Process command lines in `report_triage.json` or kernel logs

```json
{
  "kind": "exec",
  "cmd": "system_profiler SPHardwareDataType",
  "pid": 1234,
  "ts": 1600
}
```

---

## Fallback: Signature-Based Extraction

When kernel logs don't provide explicit events, extract from signatures:

```json
{
  "signatures": [
    {
      "name": "anti_vm_file_check",
      "label": "Checks for VM-related files",
      "score": 8,
      "ttp": ["T1497.001"],
      "tags": ["evasion", "anti-vm"],
      "indicators": [
        {
          "ioc": "/system/bin/qemu-props",
          "description": "Checks for QEMU emulator file"
        },
        {
          "ioc": "C:\\Windows\\System32\\drivers\\vmci.sys",
          "description": "Checks for VMware driver"
        }
      ]
    }
  ]
}
```

**Parsing Strategy:**
1. Look for signatures with tags: `evasion`, `anti-vm`, `anti-sandbox`, `anti-debug`
2. Extract IOCs from `indicators` array
3. Categorize based on signature name and IOC pattern

---

## Implementation Notes

### Priority Order for Data Sources

1. **Kernel logs** (most detailed, raw syscall data)
2. **Behavioral report signatures** (pre-categorized detections)
3. **Behavioral report network/processes** (structured data)
4. **Overview report** (metadata only)

### Handling Missing Data

The kernel log files may not always be available or may have different structures across platform versions. Implement:

1. **Graceful degradation**: If kernel logs unavailable, fall back to signatures
2. **Field tolerance**: Handle missing fields without crashing
3. **Version awareness**: Log format may change; validate expected fields

### OS Detection

Determine OS from:
1. `overview.json` → `tasks[].platform` field
2. `overview.json` → `analysis.tags` (contains OS tag)
3. File type classification in static report

```python
def detect_os(overview):
    # From task platform
    for task in overview.get('tasks', []):
        if task.get('platform'):
            return task['platform']

    # From tags
    tags = overview.get('analysis', {}).get('tags', [])
    for os in ['android', 'windows', 'linux', 'macos']:
        if os in tags:
            return os

    return None
```

---

## Sample API Calls

### Get All Behavioral Data for a Sample

```python
def get_behavioral_data(client, sample_id):
    # 1. Get overview for metadata
    overview = client.overview_report(sample_id)

    # 2. Determine tasks
    tasks = overview.get('tasks', [])
    behavioral_tasks = [t for t in tasks if t['task'].startswith('behavioral')]

    data = {
        'overview': overview,
        'behavioral_reports': [],
        'kernel_logs': []
    }

    for task in behavioral_tasks:
        task_id = task['task']
        platform = task.get('platform', 'windows')

        # 3. Get behavioral report
        try:
            report = client.task_report(sample_id, task_id)
            data['behavioral_reports'].append(report)
        except Exception:
            pass

        # 4. Get kernel logs
        log_file = {
            'windows': 'onemon.json',
            'macos': 'bigmac.json',
            'linux': 'stahp.json',
            'android': 'stahp.json'
        }.get(platform, 'onemon.json')

        try:
            logs = client.kernel_report(sample_id, task_id)
            data['kernel_logs'].append(logs)
        except Exception:
            pass

    return data
```

---

## Field Reference Summary

| Platform | Artifact Type | Primary Source | Field Path |
|----------|---------------|----------------|------------|
| Android | file | stahp.json | `kind: file_*` |
| Android | property | stahp.json | `kind: prop_get` |
| Android | package | stahp.json / signatures | `kind: pkg_query` |
| Android | port | report_triage.json | `network.flows` |
| Windows | file | onemon.json | `kind: file_*` |
| Windows | registry | onemon.json | `kind: reg_*` |
| Windows | process | signatures / onemon.json | `kind: proc_*` |
| Windows | wmi | signatures | `indicators.ioc` |
| Windows | mutex | onemon.json | `kind: mutex_*` |
| Linux | file | stahp.json | `kind: file_*` |
| Linux | process | stahp.json | `kind: proc_*` |
| Linux | environment | stahp.json | `kind: env_*` |
| macOS | file | bigmac.json | `kind: Syscall*` |
| macOS | command | report_triage.json | `processes[].cmd` |
