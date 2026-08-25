---
title: Identity
---

# Identity

Identity-related detections, suspicious logins, and lateral movement via compromised accounts.

## Example: failed logon spikes

```kusto
DeviceLogonEvents
| where LogonType == "Network" and ResultType == "Failure"
| summarize failures = count() by Account, bin(Timestamp, 1h)
| where failures > 10
```
