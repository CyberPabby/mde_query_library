# Device Queries

MDE Advanced Hunting queries for device inventory, compliance, onboarding, and security configuration.

## Queries

1. [Finding Devices Requiring Secure Boot](#finding-devices-requiring-secure-boot)
2. [Onboarded MDE Devices](#onboarded-mde-devices)
3. [Check if Tamper Protection is Enabled](#check-if-tamper-protection-is-enabled)

---

## Finding Devices Requiring Secure Boot

### Purpose

Identifies devices that are applicable for Secure Boot but are currently reported as non-compliant by Microsoft Defender for Endpoint.

### Query

```kusto
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| where IsCompliant == 0
| where ConfigurationId in (
    DeviceTvmSecureConfigurationAssessmentKB
    | where ConfigurationName contains "Secure Boot"
        or ConfigurationDescription contains "Secure Boot"
    | project ConfigurationId
)
| summarize arg_max(Timestamp, *) by DeviceId
| project
    Timestamp,
    DeviceName,
    OSPlatform,
    ConfigurationId,
    IsApplicable,
    IsCompliant
| order by DeviceName asc
```

[⬆ Back to Queries](#queries)

---

## Onboarded MDE Devices

### Purpose

Shows the latest MDE device records grouped by onboarding status and Defender sensor health state.

### Query

```kusto
DeviceInfo
| summarize arg_max(Timestamp, *) by DeviceId
| summarize Device_Count = dcount(DeviceId) by OnboardingStatus, SensorHealthState
| order by Device_Count desc
```

[⬆ Back to Queries](#queries)

---

## Check if Tamper Protection is Enabled

### Purpose

Checks whether Microsoft Defender Tamper Protection is enabled across devices.

The query combines the latest device information with Microsoft Defender secure configuration assessment data and reports the current Tamper Protection compliance status.

### Query

```kusto
DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| join kind=inner (
    DeviceTvmSecureConfigurationAssessmentKB
    | where ConfigurationName contains "Tamper"
        or ConfigurationDescription contains "Tamper"
    | project
        ConfigurationId,
        ConfigurationName,
        ConfigurationDescription,
        RiskDescription,
        RemediationOptions
) on ConfigurationId
| join kind=leftouter (
    DeviceInfo
    | summarize arg_max(Timestamp, *) by DeviceId
    | project
        DeviceId,
        LastSeen = Timestamp,
        LatestDeviceName = DeviceName,
        DeviceType,
        DeviceSubtype,
        LatestOSPlatform = OSPlatform,
        OSVersion,
        OnboardingStatus,
        SensorHealthState,
        MachineGroup
) on DeviceId
| extend TamperProtectionStatus = case(
    IsCompliant == 1, "Enabled",
    IsCompliant == 0, "Disabled / Not Compliant",
    "Unknown"
)
| project
    LastSeen,
    DeviceName = LatestDeviceName,
    DeviceType,
    DeviceSubtype,
    OSPlatform = LatestOSPlatform,
    OSVersion,
    OnboardingStatus,
    SensorHealthState,
    MachineGroup,
    TamperProtectionStatus,
    IsCompliant,
    ConfigurationId,
    ConfigurationName,
    ConfigurationDescription,
    RiskDescription,
    RemediationOptions
| order by TamperProtectionStatus asc, LastSeen desc
```

### Output

The query returns:

- Device name
- Device type and subtype
- Operating system and version
- MDE onboarding status
- Defender sensor health
- Machine group
- Tamper Protection status
- Compliance status
- Configuration ID and name
- Configuration description
- Risk description
- Remediation guidance
- Last device activity timestamp

### Tamper Protection Status

The query translates the MDE compliance value into an easier-to-read status:

- **Enabled** – Tamper Protection configuration is compliant
- **Disabled / Not Compliant** – Tamper Protection requires investigation
- **Unknown** – MDE cannot determine the current state

### Use Case

Use this query to identify devices where Microsoft Defender Tamper Protection may not be enabled or correctly configured.

It can help with:

- Defender security posture reviews
- Finding devices with Tamper Protection disabled
- Identifying configuration drift
- Prioritising remediation
- Checking MDE sensor and onboarding health at the same time

[⬆ Back to Queries](#queries)
