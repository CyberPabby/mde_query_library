---
title: Software
---

# Software

Software inventory queries, app usage, suspicious installers.

## Example: recently installed software

```kusto
DeviceEvents
| where ActionType == "SoftwareInstalled"
| project Timestamp, DeviceName, SoftwareName, InitiatingProcessAccountName
```
