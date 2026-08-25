---
title: Vulnerabilities
---

# Vulnerabilities

Collection of queries to identify vulnerable software, unpatched systems, and CVE-related telemetry.

## Example query

```kusto
// Example: devices with known vulnerable versions
DeviceInventory
| where SoftwareVersion contains "10.0"
| summarize by DeviceName, DeviceId, SoftwareName, SoftwareVersion
```
