## Finding Devices Requiring Secure Boot

### Purpose

Identifies devices in Microsoft Defender for Endpoint that are applicable for Secure Boot but are currently reported as non-compliant.

### MDE Advanced Hunting Query

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
