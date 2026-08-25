---
title: Networking
---

# Networking

Network connection queries, unusual outbound patterns, and IoC matching.

## Example: uncommon external connections

```kusto
DeviceNetworkEvents
| where RemoteIPCountry !in ("US","CA","GB")
| summarize count() by RemoteIP, RemoteIPCountry, DeviceName
```
