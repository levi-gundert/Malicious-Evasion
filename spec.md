# Triage Evasion Artifact Extractor

## Specification Document v1.0

---

## 1. Overview

### 1.1 Purpose

This system extracts anti-analysis and evasion artifacts from malware behavioral reports via the Hatching Triage API. Malware actively checks for researcher environments before executing payloads. By cataloging what malware looks for, defenders can plant these artifacts on production systems to trigger malware self-termination.

### 1.2 Supported Operating Systems

| OS | Triage Tag | Artifact Types |
|----|------------|----------------|
| Android | `android` | Files, system properties, packages, ports, API calls |
| Windows | `windows` | Files, registry keys, processes, services, WMI queries, mutexes |
| Linux | `linux` | Files, processes, environment variables, kernel modules |
| macOS | `macos` | Files, processes, launch agents, system profiler checks |

### 1.3 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         ARTIFACT EXTRACTOR                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐         │
│   │  Triage  │───▶│  Report  │───▶│  OS-Spec │───▶│  Output  │         │
│   │  Poller  │    │  Parser  │    │  Extract │    │  Writer  │         │
│   └──────────┘    └──────────┘    └──────────┘    └──────────┘         │
│        │               │               │               │                │
│        ▼               ▼               ▼               ▼                │
│   Fetch samples   Parse JSON      Extract by OS   Write JSON/YAML      │
│   by OS tag       structure       artifact type   per OS category      │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Data Models

### 2.1 Core Artifact Schema

```yaml
Artifact:
  id: string                    # Unique identifier: art-{os}-{type}-{hash8}
  os: enum                      # android | windows | linux | macos
  category: enum                # See 2.2 for OS-specific categories
  artifact_type: enum           # file | registry | process | property | etc.
  
  match_criteria:
    type: enum                  # exact | pattern | prefix | contains
    value: string               # The actual check value
    case_sensitive: boolean     # Default: true for Linux/Android, false for Windows
  
  metadata:
    description: string         # Human-readable explanation
    evasion_purpose: enum       # emulator | sandbox | debugger | vm | researcher_tools
    first_seen: datetime
    last_seen: datetime
    
  provenance:
    sample_count: integer       # Number of samples with this check
    sample_hashes: list[string] # SHA256 of samples (max 100)
    families: list[string]      # Malware family names
    confidence: float           # 0.0-1.0 based on sample count and diversity
    
  deception:
    recommended_value: string   # What to plant (for properties/registry)
    plant_as: enum              # file | directory | symlink
    permissions: string         # e.g., "755" for Linux/Android
    notes: string               # Implementation guidance
```

### 2.2 OS-Specific Categories

#### Android Categories

| Category | Description | Example Artifact |
|----------|-------------|------------------|
| `emulator_files` | QEMU/Goldfish artifacts | `/system/bin/qemu-props` |
| `emulator_properties` | Build properties indicating emulator | `ro.kernel.qemu=1` |
| `sandbox_files` | Analysis platform markers | `/data/local/tmp/cuckoo` |
| `sandbox_packages` | Installed analysis tools | `de.robv.android.xposed.installer` |
| `debugger_indicators` | Debugging detection | `TracerPid` non-zero |
| `hooking_frameworks` | Frida/Xposed detection | `/data/local/tmp/frida-server` |
| `root_indicators` | Root/Magisk detection | `/system/app/Superuser.apk` |
| `network_probes` | Debug port checks | Port 27042 (Frida) |
| `timing_checks` | Sleep acceleration detection | N/A (behavioral, not artifact) |

#### Windows Categories

| Category | Description | Example Artifact |
|----------|-------------|------------------|
| `vm_files` | VMware/VirtualBox artifacts | `C:\Windows\System32\vmGuestLib.dll` |
| `vm_registry` | Virtualization registry keys | `HKLM\SOFTWARE\VMware, Inc.` |
| `vm_processes` | VM tool processes | `vmtoolsd.exe` |
| `vm_services` | VM-related services | `VMTools` |
| `vm_wmi` | WMI queries for VM detection | `Win32_ComputerSystem.Model` |
| `sandbox_files` | Sandbox markers | `C:\agent\agent.py` |
| `sandbox_registry` | Sandbox registry indicators | Analysis tool paths |
| `sandbox_processes` | Sandbox tool processes | `python.exe` in sandbox paths |
| `sandbox_mutexes` | Known sandbox mutexes | `CuckooPipe` |
| `debugger_indicators` | Debugger detection | `IsDebuggerPresent` artifacts |
| `analysis_tools` | Researcher tool detection | `wireshark.exe`, `procmon.exe` |
| `hardware_checks` | Hardware anomalies | Low RAM, single CPU |
| `network_checks` | Network environment | Known sandbox IP ranges |
| `user_artifacts` | User behavior indicators | Recent documents, browser history |

#### Linux Categories

| Category | Description | Example Artifact |
|----------|-------------|------------------|
| `vm_files` | Hypervisor artifacts | `/sys/class/dmi/id/product_name` |
| `vm_processes` | VM guest tools | `VBoxService` |
| `container_indicators` | Docker/container detection | `/.dockerenv` |
| `sandbox_files` | Analysis environment markers | `/tmp/cuckoo-tmp` |
| `debugger_indicators` | Debugger/tracer detection | `/proc/self/status` TracerPid |
| `analysis_tools` | Installed analysis software | `strace`, `ltrace` binaries |
| `environment_vars` | Suspicious env variables | `CUCKOO=1` |

#### macOS Categories

| Category | Description | Example Artifact |
|----------|-------------|------------------|
| `vm_files` | VMware/Parallels artifacts | `/Library/Preferences/VMware Fusion` |
| `vm_processes` | VM tool processes | `VMware Tools` |
| `sandbox_files` | Analysis markers | Similar to Linux |
| `debugging_indicators` | Debug detection | `sysctl` checks |
| `analysis_tools` | Researcher tools | `Hopper`, `IDA` |

### 2.3 Sample Metadata Schema

```yaml
SampleMetadata:
  sha256: string
  sha1: string
  md5: string
  
  triage:
    sample_id: string           # Triage's internal ID
    analysis_id: string         # Specific analysis run
    submitted_at: datetime
    completed_at: datetime
    score: integer              # Triage threat score (1-10)
    
  classification:
    os: enum
    file_type: string           # APK, PE, ELF, Mach-O
    families: list[string]      # Detected malware families
    tags: list[string]          # Triage tags
    
  av_results:
    detection_ratio: string     # e.g., "45/72"
    detections: list[object]    # Engine name + detection name
```

### 2.4 Extraction Result Schema

```yaml
ExtractionResult:
  extraction_id: string         # Unique run identifier
  extracted_at: datetime
  
  parameters:
    os_filter: list[enum]       # Which OSes were processed
    lookback_days: integer      # How far back samples were fetched
    min_score: integer          # Minimum Triage score threshold
    
  statistics:
    samples_processed: integer
    artifacts_extracted: integer
    artifacts_new: integer      # Not seen in previous runs
    artifacts_updated: integer  # Existing artifacts with new samples
    by_os:
      android: integer
      windows: integer
      linux: integer
      macos: integer
    by_category: object         # Count per category
    
  artifacts: list[Artifact]
  
  errors:
    - sample_id: string
      error: string
      timestamp: datetime
```

---

## 3. Triage API Integration

### 3.1 Authentication

```yaml
Configuration:
  triage:
    api_key: string             # From environment: TRIAGE_API_KEY
    base_url: string            # Default: https://api.tria.ge (Python client default)
                                # Alternative: https://tria.ge/api/v0
    rate_limit:
      requests_per_minute: 60   # Adjust based on subscription
      retry_on_429: true
      retry_delay_seconds: 30
```

**Note**: The official Python client (`hatching-triage`) uses `https://api.tria.ge` as the base URL.

### 3.2 API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/search?query={query}` | GET | Find samples by OS tag and date range |
| `/samples/{id}` | GET | Get basic sample metadata |
| `/samples/{id}/overview.json` | GET | Get comprehensive sample overview with scores, tags, families |
| `/samples/{id}/{taskID}/report_triage.json` | GET | Get behavioral analysis report (taskID = behavioral1, behavioral2) |
| `/samples/{id}/{taskID}/logs/{platform}.json` | GET | Get kernel monitoring logs (onemon.json, bigmac.json, stahp.json) |

**Kernel Log Files by Platform:**
- Windows: `onemon.json`
- macOS: `bigmac.json`
- Linux/Android: `stahp.json`

### 3.3 Search Query Construction

**Query Syntax Operators:**
- `tag:` - OS/behavior classification
- `family:` - Malware family name
- `score:` - Threat score (1-10)
- `from:` / `to:` - Date range (format: yyyy-mm-dd or yyyy-mm-dd HH:MM:SS)
- `md5:`, `sha256:` - Hash lookups
- `AND`, `OR`, `NOT` - Boolean operators

```yaml
SearchParameters:
  android:
    query: "tag:android AND score:>=7 AND from:{lookback_date}"

  windows:
    query: "tag:windows AND score:>=7 AND from:{lookback_date}"

  linux:
    query: "tag:linux AND score:>=7 AND from:{lookback_date}"

  macos:
    query: "tag:macos AND score:>=7 AND from:{lookback_date}"
```

**Note**: Use `from:` for date filtering (not `submitted:`). Date format is `yyyy-mm-dd`.

### 3.4 Rate Limiting Strategy

```yaml
RateLimiting:
  approach: token_bucket
  
  parameters:
    bucket_size: 60             # Max burst
    refill_rate: 1              # Tokens per second
    
  behavior:
    on_limit_reached: wait      # Don't fail, wait for tokens
    on_429_response: 
      action: exponential_backoff
      initial_delay: 30
      max_delay: 300
      max_retries: 5
```

### 3.5 Response Caching

```yaml
Caching:
  enabled: true
  backend: sqlite               # Local SQLite database
  
  cache_rules:
    sample_overview:
      ttl: 7_days               # Sample metadata rarely changes
      
    behavioral_report:
      ttl: 30_days              # Reports are immutable once generated
      
  storage:
    path: ./cache/triage_cache.db
    max_size_mb: 500
```

---

## 4. Extraction Logic by OS

### 4.1 Android Extraction

#### 4.1.1 File Existence Checks

**Source in Triage Report:** `behavioral.filesystem` array

**Detection Logic:**

```yaml
FileExistenceExtraction:
  scan_operations:
    - stat
    - access
    - open (with O_RDONLY and immediate close)
    - exists
    
  evasion_path_patterns:
    emulator:
      - regex: "/system/bin/qemu.*"
      - regex: "/dev/qemu.*"
      - regex: "/dev/goldfish.*"
      - contains: "goldfish"
      - contains: "ranchu"
      
    sandbox:
      - regex: "/data/local/tmp/(frida|cuckoo|strace).*"
      - contains: "sandbox"
      - contains: "triage"
      - contains: "analysis"
      
    hooking:
      - contains: "frida"
      - contains: "xposed"
      - contains: "substrate"
      
    root:
      - exact: "/system/app/Superuser.apk"
      - exact: "/system/xbin/su"
      - exact: "/sbin/su"
      - regex: "/data/data/com\.(noshufou|koushikdutta|thirdparty).*superuser.*"
      
  output_artifact:
    artifact_type: file
    match_criteria:
      type: exact | pattern      # Based on how specific the path is
      value: {extracted_path}
    deception:
      plant_as: file | directory  # Based on path structure
      recommended_value: ""       # Empty file unless specific content needed
```

#### 4.1.2 System Property Checks

**Source in Triage Report:** `behavioral.properties_read` array

**Detection Logic:**

```yaml
PropertyExtraction:
  evasion_properties:
    emulator:
      - property: "ro.kernel.qemu"
        evasion_value: "1"
        deception_value: "1"
        
      - property: "ro.hardware"
        evasion_values: ["goldfish", "ranchu", "generic"]
        deception_value: "goldfish"
        
      - property: "ro.product.model"
        evasion_patterns: ["sdk", "emulator", "generic"]
        deception_value: "sdk_gphone_x86_64"
        
      - property: "ro.build.fingerprint"
        evasion_patterns: ["generic", "sdk", "test-keys"]
        deception_value: "generic/sdk/generic:11/RSR1/eng:userdebug/test-keys"
        
      - property: "ro.product.device"
        evasion_values: ["generic", "generic_x86"]
        deception_value: "generic"
        
      - property: "ro.build.characteristics"
        evasion_value: "emulator"
        deception_value: "emulator"
        
      - property: "init.svc.qemu-props"
        evasion_value: "running"
        deception_value: "running"
        
    debugging:
      - property: "ro.debuggable"
        evasion_value: "1"
        deception_value: "1"
        
  output_artifact:
    artifact_type: property
    match_criteria:
      type: exact
      value: {property_name}
    deception:
      recommended_value: {deception_value}
```

#### 4.1.3 Package Queries

**Source in Triage Report:** `behavioral.package_queries` array

**Detection Logic:**

```yaml
PackageExtraction:
  evasion_packages:
    hooking:
      - "de.robv.android.xposed.installer"
      - "com.saurik.substrate"
      - "com.topjohnwu.magisk"
      
    analysis:
      - "com.frida.server"
      - "com.cuckoo.sandbox"
      - "org.proxydroid"
      
    root:
      - "com.noshufou.android.su"
      - "com.thirdparty.superuser"
      - "eu.chainfire.supersu"
      - "com.koushikdutta.superuser"
      
  output_artifact:
    artifact_type: package
    match_criteria:
      type: exact
      value: {package_name}
    deception:
      notes: "Create matching directory in /data/data/"
```

#### 4.1.4 Network Port Probes

**Source in Triage Report:** `behavioral.network` array

**Detection Logic:**

```yaml
PortProbeExtraction:
  connection_filter:
    destination: "127.0.0.1" | "localhost"
    result: "connection_refused" | "timeout"  # Probing, not connecting
    
  evasion_ports:
    frida:
      - port: 27042
        description: "Frida default port"
      - port: 27043
        description: "Frida alternate port"
        
    debugging:
      - port: 5037
        description: "ADB default port"
      - port: 5555
        description: "ADB wireless"
        
    analysis:
      - port: 8080
        description: "Common proxy port"
      - port: 8100
        description: "Appium port"
        
  output_artifact:
    artifact_type: port
    match_criteria:
      type: exact
      value: {port_number}
    deception:
      notes: "Bind listener on this port"
```

### 4.2 Windows Extraction

#### 4.2.1 File Existence Checks

**Source in Triage Report:** `behavioral.filesystem` array

**Detection Logic:**

```yaml
WindowsFileExtraction:
  scan_operations:
    - stat
    - open
    - access
    - GetFileAttributes
    
  evasion_path_patterns:
    vmware:
      - exact: "C:\\Windows\\System32\\drivers\\vmhgfs.sys"
      - exact: "C:\\Windows\\System32\\drivers\\vmmouse.sys"
      - exact: "C:\\Windows\\System32\\drivers\\vmci.sys"
      - exact: "C:\\Program Files\\VMware\\VMware Tools\\"
      - contains: "vmware"
      
    virtualbox:
      - exact: "C:\\Windows\\System32\\drivers\\VBoxMouse.sys"
      - exact: "C:\\Windows\\System32\\drivers\\VBoxGuest.sys"
      - exact: "C:\\Windows\\System32\\drivers\\VBoxSF.sys"
      - exact: "C:\\Program Files\\Oracle\\VirtualBox Guest Additions\\"
      - contains: "vbox"
      
    hyperv:
      - exact: "C:\\Windows\\System32\\drivers\\vmbus.sys"
      - contains: "integ"
      
    sandbox:
      - contains: "\\agent\\"
      - contains: "\\cuckoo\\"
      - contains: "\\sandbox\\"
      - contains: "\\sample\\"
      - regex: "C:\\\\Users\\\\(cuckoo|sandbox|malware|analyst)\\\\"
      
    analysis_tools:
      - contains: "\\wireshark\\"
      - contains: "\\ida\\"
      - contains: "\\x64dbg\\"
      - contains: "\\ollydbg\\"
      - contains: "\\procmon\\"
      
  output_artifact:
    artifact_type: file
    match_criteria:
      type: exact | contains | pattern
      value: {extracted_path}
      case_sensitive: false
    deception:
      plant_as: file | directory
```

#### 4.2.2 Registry Key Checks

**Source in Triage Report:** `behavioral.registry` array

**Detection Logic:**

```yaml
RegistryExtraction:
  scan_operations:
    - RegOpenKey
    - RegQueryValue
    - RegEnumKey
    
  evasion_keys:
    vmware:
      - key: "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools"
        check_type: exists
        
      - key: "HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0"
        value: "Identifier"
        evasion_contains: "vmware"
        
    virtualbox:
      - key: "HKLM\\SOFTWARE\\Oracle\\VirtualBox Guest Additions"
        check_type: exists
        
      - key: "HKLM\\HARDWARE\\ACPI\\DSDT\\VBOX__"
        check_type: exists
        
    hardware:
      - key: "HKLM\\HARDWARE\\DESCRIPTION\\System"
        value: "SystemBiosVersion"
        evasion_contains: ["vmware", "virtualbox", "vbox", "qemu", "bochs"]
        
      - key: "HKLM\\HARDWARE\\DESCRIPTION\\System"
        value: "VideoBiosVersion"
        evasion_contains: ["virtualbox"]
        
    sandbox:
      - key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion"
        value: "ProductId"
        evasion_values: ["55274-640-2673064-23950"]  # Known sandbox IDs
        
  output_artifact:
    artifact_type: registry
    match_criteria:
      type: exact | contains
      key: {registry_key}
      value: {value_name}        # Optional
    deception:
      recommended_value: {evasion_value}
```

#### 4.2.3 Process Enumeration

**Source in Triage Report:** `behavioral.processes` array

**Detection Logic:**

```yaml
ProcessExtraction:
  scan_operations:
    - CreateToolhelp32Snapshot
    - Process32First/Next
    - EnumProcesses
    - OpenProcess (with query rights)
    
  evasion_processes:
    vmware:
      - "vmtoolsd.exe"
      - "vmwaretray.exe"
      - "vmwareuser.exe"
      - "vmacthlp.exe"
      
    virtualbox:
      - "VBoxService.exe"
      - "VBoxTray.exe"
      
    sandbox:
      - "python.exe"            # Common in sandboxes
      - "pythonw.exe"
      - "agent.exe"
      - "analyzer.exe"
      
    analysis_tools:
      - "wireshark.exe"
      - "fiddler.exe"
      - "procmon.exe"
      - "procexp.exe"
      - "tcpview.exe"
      - "autoruns.exe"
      - "idaq.exe"
      - "idaq64.exe"
      - "x32dbg.exe"
      - "x64dbg.exe"
      - "ollydbg.exe"
      - "immunitydebugger.exe"
      - "petools.exe"
      - "lordpe.exe"
      - "regshot.exe"
      
    debugging:
      - "devenv.exe"
      - "windbg.exe"
      
  output_artifact:
    artifact_type: process
    match_criteria:
      type: exact
      value: {process_name}
      case_sensitive: false
    deception:
      notes: "Run dummy process with this name"
```

#### 4.2.4 WMI Queries

**Source in Triage Report:** `behavioral.wmi` array

**Detection Logic:**

```yaml
WMIExtraction:
  evasion_queries:
    hardware:
      - class: "Win32_ComputerSystem"
        property: "Manufacturer"
        evasion_contains: ["vmware", "virtualbox", "microsoft corporation", "xen"]
        
      - class: "Win32_ComputerSystem"
        property: "Model"
        evasion_contains: ["vmware", "virtualbox", "virtual"]
        
      - class: "Win32_BIOS"
        property: "SerialNumber"
        evasion_contains: ["vmware", "virtualbox"]
        
      - class: "Win32_BIOS"
        property: "Version"
        evasion_contains: ["vbox", "vmware", "bochs", "qemu"]
        
      - class: "Win32_DiskDrive"
        property: "Model"
        evasion_contains: ["vmware", "vbox", "virtual"]
        
      - class: "Win32_NetworkAdapter"
        property: "MACAddress"
        evasion_prefixes: ["00:0C:29", "00:50:56", "08:00:27"]  # VMware, VirtualBox
        
    environment:
      - class: "Win32_ComputerSystem"
        property: "NumberOfProcessors"
        evasion_condition: "< 2"
        
      - class: "Win32_ComputerSystem"
        property: "TotalPhysicalMemory"
        evasion_condition: "< 2147483648"  # < 2GB
        
  output_artifact:
    artifact_type: wmi
    match_criteria:
      class: {wmi_class}
      property: {property_name}
    deception:
      notes: "Requires WMI spoofing at driver level"
```

#### 4.2.5 Mutex Checks

**Source in Triage Report:** `behavioral.mutexes` or `behavioral.sync_objects`

**Detection Logic:**

```yaml
MutexExtraction:
  operations:
    - CreateMutex
    - OpenMutex
    
  evasion_mutexes:
    sandbox:
      - "CuckooPipe"
      - "JoesSandbox"
      - "AnyRunMutex"
      
    analysis_tools:
      - "WiresharkMutex"
      - "FiddlerMutex"
      
  output_artifact:
    artifact_type: mutex
    match_criteria:
      type: exact | contains
      value: {mutex_name}
    deception:
      notes: "Create mutex with this name on system startup"
```

### 4.3 Linux Extraction

#### 4.3.1 File Existence Checks

**Source in Triage Report:** `behavioral.filesystem` array

**Detection Logic:**

```yaml
LinuxFileExtraction:
  evasion_path_patterns:
    vm:
      - exact: "/.dockerenv"
      - exact: "/run/.containerenv"
      - regex: "/sys/class/dmi/id/(product_name|sys_vendor)"
      - exact: "/sys/hypervisor/type"
      - contains: "vmware"
      - contains: "virtualbox"
      - contains: "vbox"
      
    container:
      - exact: "/.dockerenv"
      - exact: "/run/.containerenv"
      - regex: "/proc/1/cgroup"
      
    sandbox:
      - contains: "/tmp/cuckoo"
      - contains: "/opt/sandbox"
      - contains: "/analysis/"
      
    debugging:
      - exact: "/proc/self/status"       # For TracerPid check
      - exact: "/proc/self/stat"
      
    analysis_tools:
      - exact: "/usr/bin/strace"
      - exact: "/usr/bin/ltrace"
      - exact: "/usr/bin/gdb"
      
  output_artifact:
    artifact_type: file
    match_criteria:
      type: exact | contains | pattern
      value: {extracted_path}
      case_sensitive: true
    deception:
      plant_as: file | directory
      permissions: "755" | "644"
```

#### 4.3.2 Process Checks

**Source in Triage Report:** `behavioral.processes` array

**Detection Logic:**

```yaml
LinuxProcessExtraction:
  evasion_processes:
    vm:
      - "VBoxService"
      - "VBoxClient"
      - "vmtoolsd"
      - "qemu-ga"
      
    debugging:
      - "strace"
      - "ltrace"
      - "gdb"
      
    analysis:
      - "cuckoo"
      - "tcpdump"
      - "tshark"
```

#### 4.3.3 Environment Variable Checks

**Source in Triage Report:** `behavioral.environment` array

**Detection Logic:**

```yaml
EnvVarExtraction:
  evasion_variables:
    sandbox:
      - name: "CUCKOO"
        check_type: exists
        
      - name: "SANDBOX"
        check_type: exists
        
      - name: "MALWARE_ANALYSIS"
        check_type: exists
        
    container:
      - name: "container"
        value_contains: "docker"
```

### 4.4 macOS Extraction

#### 4.4.1 File Existence Checks

**Source in Triage Report:** `behavioral.filesystem` array

**Detection Logic:**

```yaml
MacOSFileExtraction:
  evasion_path_patterns:
    vmware:
      - exact: "/Library/Application Support/VMware Tools"
      - exact: "/Applications/VMware Tools.app"
      
    parallels:
      - exact: "/Library/Parallels Guest Tools"
      
    virtualbox:
      - exact: "/Library/Extensions/VBoxGuest.kext"
      
    analysis:
      - contains: "/Users/analysis/"
      - contains: "/Users/malware/"
      - contains: "sandbox"
```

#### 4.4.2 System Profiler Checks

**Source in Triage Report:** `behavioral.commands` array

**Detection Logic:**

```yaml
SystemProfilerExtraction:
  commands_to_watch:
    - regex: "system_profiler SP(Hardware|Software)DataType"
    - regex: "sysctl hw\\.(model|machine)"
    - exact: "ioreg -l"
    
  evasion_outputs:
    - field: "hw.model"
      evasion_contains: ["vmware", "virtualbox", "parallels"]
```

---

## 5. Aggregation and Confidence Scoring

### 5.1 Artifact Deduplication

```yaml
DeduplicationRules:
  exact_match:
    # Same OS + artifact_type + value = same artifact
    key_fields:
      - os
      - artifact_type
      - match_criteria.value
      
  merge_behavior:
    # When duplicate found, merge provenance
    action: merge
    fields_to_merge:
      - provenance.sample_count        # Sum
      - provenance.sample_hashes       # Union (max 100)
      - provenance.families            # Union
    fields_to_update:
      - metadata.last_seen             # Latest timestamp
      - provenance.confidence          # Recalculate
```

### 5.2 Confidence Calculation

```yaml
ConfidenceScoring:
  formula: |
    base_score = min(sample_count / 10, 0.5)    # Max 0.5 from sample count
    family_bonus = min(unique_families / 5, 0.3) # Max 0.3 from family diversity
    recency_bonus = 0.2 if last_seen > 30_days_ago else 0.1
    
    confidence = base_score + family_bonus + recency_bonus
    confidence = min(confidence, 1.0)
    
  thresholds:
    high:   ">= 0.8"    # 8+ samples from 4+ families, recent
    medium: ">= 0.5"    # 5+ samples or 2+ families
    low:    "< 0.5"     # Few samples, single family
```

### 5.3 Artifact Filtering

```yaml
OutputFiltering:
  include_if:
    - confidence >= 0.3
    - sample_count >= 2
    
  exclude_if:
    - artifact is known legitimate      # e.g., checking for legitimate software
    - path is user-specific             # e.g., specific usernames
    
  known_legitimate_paths:
    windows:
      - "C:\\Program Files\\Google\\Chrome\\"     # Just checking for Chrome
      - "C:\\Program Files\\Mozilla Firefox\\"
    android:
      - "/data/data/com.google."                  # Google apps
```

---

## 6. Output Formats

### 6.1 Primary Output: artifacts.json

```yaml
OutputSchema:
  file: artifacts.json
  
  structure:
    version: string             # Schema version: "1.0"
    generated_at: datetime
    extraction_id: string
    
    statistics:
      total_artifacts: integer
      by_os:
        android: integer
        windows: integer
        linux: integer
        macos: integer
      by_confidence:
        high: integer
        medium: integer
        low: integer
        
    artifacts:
      android: list[Artifact]
      windows: list[Artifact]
      linux: list[Artifact]
      macos: list[Artifact]
```

### 6.2 OS-Specific Outputs

```yaml
PerOSOutputs:
  files:
    - artifacts_android.json
    - artifacts_windows.json
    - artifacts_linux.json
    - artifacts_macos.json
    
  purpose: "For consumers that only need one OS"
```

### 6.3 Deception-Ready Outputs

```yaml
DeceptionOutputs:
  android:
    file: android_deception_config.yaml
    content:
      files_to_create: list[path]
      properties_to_set: dict[name, value]
      packages_to_fake: list[package_name]
      ports_to_bind: list[port]
      
  windows:
    file: windows_deception_config.yaml
    content:
      files_to_create: list[path]
      registry_to_create: list[object]
      processes_to_run: list[process_name]
      mutexes_to_create: list[mutex_name]
      services_to_fake: list[service_name]
      
  linux:
    file: linux_deception_config.yaml
    content:
      files_to_create: list[path]
      env_vars_to_set: dict[name, value]
      processes_to_fake: list[process_name]
```

### 6.4 Change Report

```yaml
ChangeReport:
  file: extraction_changes.json
  
  content:
    extraction_id: string
    compared_to: string         # Previous extraction_id
    
    new_artifacts: list[Artifact]
    updated_artifacts:
      - artifact_id: string
        changes:
          - field: string
            old_value: any
            new_value: any
    removed_artifacts: list[artifact_id]
    
    summary:
      new_count: integer
      updated_count: integer
      removed_count: integer
```

---

## 7. Configuration

### 7.1 Full Configuration Schema

```yaml
config:
  # === TRIAGE API ===
  triage:
    api_key: "${TRIAGE_API_KEY}"
    base_url: "https://tria.ge/api/v0"
    rate_limit:
      requests_per_minute: 60
      retry_on_429: true
      max_retries: 5
      
  # === EXTRACTION PARAMETERS ===
  extraction:
    lookback_days: 7            # How far back to fetch samples
    min_score: 7                # Minimum Triage threat score
    os_targets:                 # Which OSes to process
      - android
      - windows
      - linux
      - macos
    max_samples_per_os: 500     # Limit per extraction run
    
  # === FILTERING ===
  filtering:
    min_sample_count: 2         # Require at least N samples
    min_confidence: 0.3         # Minimum confidence to include
    exclude_patterns:           # Paths to never include
      - regex: "C:\\\\Users\\\\[^\\\\]+\\\\AppData"  # User-specific
      - contains: "temp"        # Too generic
      
  # === OUTPUT ===
  output:
    directory: "./output"
    formats:
      - json                    # Always output JSON
      - yaml                    # Also output YAML
    split_by_os: true           # Create per-OS files
    generate_deception_configs: true
    generate_change_report: true
    
  # === CACHING ===
  cache:
    enabled: true
    path: "./cache/triage_cache.db"
    max_size_mb: 500
    
  # === LOGGING ===
  logging:
    level: INFO
    file: "./logs/extractor.log"
    format: "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
```

### 7.2 Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TRIAGE_API_KEY` | Yes | Hatching Triage API key |
| `EXTRACTOR_CONFIG` | No | Path to config file (default: ./config.yaml) |
| `EXTRACTOR_OUTPUT_DIR` | No | Override output directory |
| `EXTRACTOR_LOG_LEVEL` | No | Override log level |

---

## 8. CLI Interface

### 8.1 Commands

```bash
# Full extraction for all OSes
python extractor.py extract

# Extract specific OS only
python extractor.py extract --os android
python extractor.py extract --os windows,linux

# Extract with custom lookback
python extractor.py extract --days 14

# Extract single sample (for testing)
python extractor.py extract-sample <sample_id>

# View cached statistics
python extractor.py stats

# Clear cache
python extractor.py clear-cache

# Validate configuration
python extractor.py validate-config

# Generate deception configs from existing artifacts
python extractor.py generate-deception --input artifacts.json
```

### 8.2 Output Examples

```bash
$ python extractor.py extract --os android --days 7

Triage Artifact Extractor v1.0
==============================

Configuration:
  OSes: android
  Lookback: 7 days
  Min score: 7

Fetching samples...
  Found 127 Android samples

Processing samples:
  [████████████████████████████████████████] 127/127

Extraction complete:
  Samples processed: 127
  Artifacts extracted: 342
    - emulator_files: 45
    - emulator_properties: 23
    - sandbox_files: 67
    - hooking_frameworks: 89
    - root_indicators: 52
    - network_probes: 34
    - sandbox_packages: 32
    
  New artifacts: 12
  Updated artifacts: 89

Output written to:
  - ./output/artifacts.json
  - ./output/artifacts_android.json
  - ./output/android_deception_config.yaml
  - ./output/extraction_changes.json
```

---

## 9. Error Handling

### 9.1 Error Categories

```yaml
ErrorHandling:
  api_errors:
    401_unauthorized:
      action: fatal
      message: "Invalid API key"
      
    429_rate_limited:
      action: retry
      strategy: exponential_backoff
      max_retries: 5
      
    500_server_error:
      action: retry
      strategy: linear_backoff
      max_retries: 3
      
    timeout:
      action: retry
      max_retries: 3
      
  parsing_errors:
    missing_behavioral_report:
      action: skip_sample
      log_level: WARNING
      
    malformed_json:
      action: skip_sample
      log_level: ERROR
      
    unexpected_structure:
      action: skip_field
      log_level: WARNING
      
  validation_errors:
    invalid_artifact:
      action: skip_artifact
      log_level: WARNING
```

### 9.2 Error Reporting

```yaml
ErrorReport:
  included_in_output: true
  
  structure:
    total_errors: integer
    by_category:
      api_errors: integer
      parsing_errors: integer
      validation_errors: integer
    details:
      - timestamp: datetime
        category: string
        sample_id: string
        message: string
        stack_trace: string    # Only in debug mode
```

---

## 10. Testing Strategy

### 10.1 Unit Tests

```yaml
UnitTests:
  triage_client:
    - test_authentication
    - test_rate_limiting
    - test_search_query_construction
    - test_response_parsing
    
  extractors:
    - test_android_file_extraction
    - test_android_property_extraction
    - test_windows_file_extraction
    - test_windows_registry_extraction
    - test_windows_process_extraction
    - test_linux_file_extraction
    
  aggregation:
    - test_deduplication
    - test_confidence_scoring
    - test_filtering
    
  output:
    - test_json_generation
    - test_yaml_generation
    - test_deception_config_generation
```

### 10.2 Integration Tests

```yaml
IntegrationTests:
  # Use saved Triage responses (don't hit live API)
  fixtures:
    - android_banking_trojan.json
    - windows_ransomware.json
    - linux_botnet.json
    
  tests:
    - test_full_extraction_pipeline
    - test_incremental_extraction
    - test_multi_os_extraction
```

### 10.3 Test Fixtures

```yaml
TestFixtures:
  location: ./tests/fixtures/
  
  files:
    - name: android_anatsa_behavioral.json
      description: "Real Anatsa banking trojan behavioral report"
      expected_artifacts:
        - type: file
          value: "/system/bin/qemu-props"
        - type: property
          value: "ro.kernel.qemu"
        - type: port
          value: 27042
          
    - name: windows_emotet_behavioral.json
      description: "Real Emotet behavioral report"
      expected_artifacts:
        - type: file
          value: "C:\\Windows\\System32\\drivers\\vmci.sys"
        - type: registry
          key: "HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools"
        - type: process
          value: "procmon.exe"
```

---

## 11. Project Structure

```
triage-artifact-extractor/
├── README.md
├── requirements.txt
├── setup.py
├── config.yaml.example
│
├── extractor/
│   ├── __init__.py
│   ├── cli.py                    # CLI entry point
│   ├── config.py                 # Configuration loading
│   │
│   ├── triage/
│   │   ├── __init__.py
│   │   ├── client.py             # Triage API client
│   │   ├── models.py             # Response models
│   │   └── cache.py              # Response caching
│   │
│   ├── extractors/
│   │   ├── __init__.py
│   │   ├── base.py               # Base extractor class
│   │   ├── android.py            # Android-specific extraction
│   │   ├── windows.py            # Windows-specific extraction
│   │   ├── linux.py              # Linux-specific extraction
│   │   └── macos.py              # macOS-specific extraction
│   │
│   ├── aggregation/
│   │   ├── __init__.py
│   │   ├── deduplicator.py       # Artifact deduplication
│   │   ├── scorer.py             # Confidence scoring
│   │   └── filter.py             # Output filtering
│   │
│   ├── output/
│   │   ├── __init__.py
│   │   ├── json_writer.py        # JSON output
│   │   ├── yaml_writer.py        # YAML output
│   │   ├── deception_writer.py   # Deception config generation
│   │   └── change_reporter.py    # Change report generation
│   │
│   └── models/
│       ├── __init__.py
│       ├── artifact.py           # Artifact data model
│       ├── sample.py             # Sample metadata model
│       └── extraction.py         # Extraction result model
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py               # Pytest fixtures
│   ├── fixtures/                 # Test data files
│   │   ├── android_anatsa_behavioral.json
│   │   ├── windows_emotet_behavioral.json
│   │   └── ...
│   ├── unit/
│   │   ├── test_triage_client.py
│   │   ├── test_android_extractor.py
│   │   ├── test_windows_extractor.py
│   │   └── ...
│   └── integration/
│       └── test_full_pipeline.py
│
├── output/                       # Generated outputs (gitignored)
├── cache/                        # Cache database (gitignored)
└── logs/                         # Log files (gitignored)
```

---

## 12. Dependencies

```
# requirements.txt

# Core
requests>=2.28.0
pydantic>=2.0.0
pyyaml>=6.0

# CLI
click>=8.0.0
rich>=13.0.0              # Pretty terminal output

# Caching
sqlite-utils>=3.30

# Testing
pytest>=7.0.0
pytest-cov>=4.0.0
responses>=0.23.0         # Mock HTTP responses

# Development
black>=23.0.0
isort>=5.12.0
mypy>=1.0.0
```

---

## 13. Future Enhancements

### 13.1 Phase 2: Scheduled Extraction

```yaml
ScheduledExtraction:
  description: "Run extraction automatically via cron/scheduler"
  
  features:
    - Daily extraction runs
    - Automatic GitHub push
    - Slack/Discord notifications on new artifacts
    - Artifact decay (remove stale artifacts)
```

### 13.2 Phase 3: Multi-Source Support

```yaml
AdditionalSources:
  description: "Pull from sources beyond Triage"
  
  sources:
    - name: MalwareBazaar
      url: "https://bazaar.abuse.ch/api/v1/"
      artifact_types: ["file"]
      
    - name: VirusTotal
      url: "https://www.virustotal.com/api/v3/"
      artifact_types: ["file", "registry", "process"]
      
    - name: Any.Run
      url: "https://api.any.run/"
      artifact_types: ["all"]
```

### 13.3 Phase 4: Artifact Effectiveness Tracking

```yaml
EffectivenessTracking:
  description: "Track which artifacts actually get triggered by malware"
  
  data_sources:
    - Telemetry from deployed deception systems
    - Correlation with malware detection events
    
  outputs:
    - Artifact effectiveness scores
    - Recommendations for artifact pruning
    - High-value artifact identification
```

---

## 14. Appendix: Triage Report Structure Reference

> **Note**: Behavioral data comes from multiple sources: the main behavioral report
> (`report_triage.json`) and platform-specific kernel logs. See `docs/behavioral_data_mapping.md`
> for detailed field mappings.

### 14.1 Main Behavioral Report Structure (report_triage.json)

```yaml
TriageReport:
  version: string               # Report version
  sample:
    id: string
    target: string
    md5: string
    sha256: string
    size: integer

  task:
    task: string               # "behavioral1", "behavioral2"
    backend: string            # Platform backend
    resource: string           # Analysis resource used

  processes:                   # Processes that ran during analysis
    - procid: integer          # Internal process ID
      procid_parent: integer
      pid: integer             # System PID
      ppid: integer
      cmd: string              # Command line
      image: string            # Executable path
      orig: boolean            # Original submitted process
      started: integer         # Timestamp (ms)
      terminated: integer

  signatures:                  # Behavioral detections
    - name: string
      label: string
      score: integer
      ttp: list[string]        # MITRE ATT&CK TTPs
      tags: list[string]
      indicators:              # IOCs associated with this signature
        - ioc: string
          description: string

  network:
    flows:
      - src: string            # "ip:port"
        dst: string
        proto: string          # tcp, udp
        pid: integer
        status: string         # connected, refused, timeout

  dumped:                      # Files created/dropped
    - at: integer              # Timestamp
      pid: integer
      path: string
      name: string
      kind: string             # "martian" for dropped files
      md5: string
      sha256: string

  extracted:                   # Extracted configs/artifacts
    - ...
```

### 14.2 Kernel Log Structure (stahp.json / onemon.json / bigmac.json)

**Android/Linux Kernel Log (stahp.json):**
```yaml
# Each line is a JSON object
FileOperation:
  kind: string                 # file_stat, file_open, file_access
  path: string
  pid: integer
  ret: integer                 # -1 = not found, 0 = success
  ts: integer                  # Timestamp

PropertyRead:                  # Android only
  kind: "prop_get"
  name: string                 # Property name (e.g., "ro.kernel.qemu")
  value: string                # Value returned
  pid: integer
  ts: integer

PackageQuery:                  # Android only
  kind: "pkg_query"
  package: string
  installed: boolean
  pid: integer
  ts: integer

EnvironmentRead:               # Linux
  kind: "env_get"
  name: string
  value: string
  pid: integer
  ts: integer
```

**Windows Kernel Log (onemon.json):**
```yaml
FileOperation:
  kind: string                 # file_open, file_stat
  path: string
  pid: integer
  ret: integer
  ts: integer

RegistryOperation:
  kind: string                 # reg_open, reg_query
  key: string
  value: string                # Value name (optional)
  data: string                 # Value data (if read)
  pid: integer
  ret: integer
  ts: integer

MutexOperation:
  kind: string                 # mutex_open, mutex_create
  name: string
  pid: integer
  ret: integer
  ts: integer

ProcessEnumeration:
  kind: "proc_enum"
  pid: integer
  ts: integer
```

**macOS Kernel Log (bigmac.json):**
```yaml
SyscallEvent:
  kind: string                 # SyscallSI, SyscallSII, etc.
  args: list[string]           # Syscall arguments (paths, etc.)
  pid: integer
  ret: integer
  ts: integer

ExecEvent:
  kind: "exec"
  cmd: string                  # Full command line
  pid: integer
  ts: integer
```

### 14.3 Fallback: Extracting from Signatures

When kernel logs are unavailable, extract evasion artifacts from signatures:

```yaml
# Look for signatures with these tags:
SignatureTags:
  - evasion
  - anti-vm
  - anti-sandbox
  - anti-debug
  - anti-analysis

# Extract IOCs from indicators:
Example:
  name: "anti_vm_file_check"
  indicators:
    - ioc: "/system/bin/qemu-props"
      description: "Checks for QEMU emulator"
```
