---
title: Server hardening
---

# Server hardening

Guidelines and queries to check secure configuration, local admin, services, and attack surface reduction.

## Example checks

- Local admin accounts
- Unusual services
- Unpatched SMB versions

```kusto
// Example: devices with local admin membership
DeviceLocalUsers
| where IsDomainJoined == false and AccountType == "LocalAdmin"
| project DeviceName, AccountName
```
