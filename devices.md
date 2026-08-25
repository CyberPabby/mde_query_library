---
title: Devices
---

# Devices

Queries and inventory checks for devices, OS versions, telemetry coverage.

## Example device inventory

```kusto
DeviceInventory
| summarize by DeviceName, OSVersion, LastSeen
```
