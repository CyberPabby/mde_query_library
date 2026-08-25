---
title: Threat hunting
---

# Threat hunting

Reusable hunting queries, hunting playbooks, and notes on tuning alerts and reducing false positives.

## Example hunting query

```kusto
// Suspicious parent-child process relationships
DeviceProcessEvents
| where ProcessCommandLine has "powershell" and ParentImage has_any ("cmd.exe","explorer.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName=ParentImage, ProcessFileName=FileName, ProcessCommandLine
```
