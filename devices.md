# Device Queries

MDE Advanced Hunting queries for device inventory, compliance, onboarding, and security configuration.

## Queries

1. [Finding Devices Requiring Secure Boot](#finding-devices-requiring-secure-boot)
2. [Onboarded MDE Devices](#onboarded-mde-devices)

---

## Finding Devices Requiring Secure Boot

### Purpose

Identifies devices that are applicable for Secure Boot but are currently reported as non-compliant by Microsoft Defender for Endpoint.

### Query

```kusto
let SecureBootConfig =
DeviceTvmSecureConfigurationAssessmentKB
| where ConfigurationName has_any ("Secure Boot", "Secure boot")
   or ConfigurationDescription has_any ("Secure Boot", "Secure boot")
| project
    ConfigurationId,
    ConfigurationName,
    ConfigurationDescription,
    RiskDescription,
    ConfigurationImpact,
    Tags;

DeviceTvmSecureConfigurationAssessment
| where IsApplicable == 1
| where IsCompliant == 0
| join kind=inner SecureBootConfig on ConfigurationId
| summarize arg_max(Timestamp, *) by DeviceId, ConfigurationId
| project
    Timestamp,
    DeviceName,
    OSPlatform,
    ConfigurationId,
    ConfigurationName,
    ConfigurationDescription,
    RiskDescription,
    ConfigurationImpact,
    Tags
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
