Behaviours worth detecting:

1. Repeated enumeration of local groups by the SYSTEM account (A-016, A-019, A-020, A-021, A-022, A-024, A-025, A-026)
2. Service installation by an unidentified user (A-031)
3. Brute force login attempt against the Administrator account (A-009)
4. Multiple login attempts by the SYSTEM account within a short period (A-010, A-012, A-014, A-017, A-027, A-029)

MITRE ATT&CK Mapping:

1. Directory Services Reconnaissance (T1089)
2. Persistence - Service (T1055)
3. Brute Force (T1110)
4. Account Maintenance (T1136)

Detection Rules:

1. Alert on repeated enumeration of local groups by the SYSTEM account:

```yaml
rule: Repeated_Enumeration_of_Local_Groups_by_SYSTEM_Account
id: 7c61b146-364c-46e1-97b0-d7344734080d
description: Detects repeated enumeration of local groups by the SYSTEM account
logsource: Security Event Log
detection:
  - sequence:
      - event_data.UserName == "SYSTEM"
      - event_data.LogonType == 2 or event_data.LogonType == 10 or event_data.LogonType == 11 or event_data.LogonType
== 12
      - event_data.SubjectLogonId == 4294967295
      - within: 1 hour
      - event_data.TargetName contains "groups"
      - event_data.EventID == 4657
      - event_data.EventID == 4658
      - event_data.EventID == 4660
      - event_data.EventID == 4663
      - event_data.EventID == 4659
      - event_data.EventID == 4662
      - event_data.EventID == 4661
      - event_data.EventID == 4656
      - event_data.EventID == 4664
      - event_data.EventID == 4665
      - event_data.EventID == 4654
      - event_data.EventID == 4655
      - event_data.EventID == 4666
      - event_data.EventID == 4653
      - event_data.EventID == 4651
      - event_data.EventID == 4667
      - event_data.EventID == 4652
      - event_data.EventID == 4650

tags:
  - Account Enumeration
  - Privileged Accounts
```

2. Alert on service installation by an unidentified user (A-031):

```yaml
rule: Service_Installation_by_Unknown_User
id: e0608911-7e25-4222-84d0-45e3211928b8
description: Detects service installation by an unidentified user
logsource: Security Event Log
detection:
  - sequence:
      - event_data.UserName != "SYSTEM" and event_data.UserName != "NT AUTHORITY\SYSTEM"
      - event_data.EventID == 4688
      - event_data.TargetObjectName contains "Service"
      - event_data.OperationName == "Create"

tags:
  - Persistence
  - Privileged Accounts
```

3. Alert on brute force login attempt against the Administrator account (A-009):

```yaml
rule: Brute_Force_Login_Attempt_against_Administrator_Account
id: 0a04b276-4d3b-4e51-831d-b218f5e0b16b
description: Detects brute force login attempt against the Administrator account
logsource: Security Event Log
detection:
  - sequence:
      - event_data.UserName == "Administrator"
      - event_data.LogonType == 3 or event_data.LogonType == 5
      - within: 1 minute
      - event_data.EventID == 4625
      - event_data.TargetName contains "NTLM_V2"
      - event_data.TargetName contains "NTLM_SSSP"
      - event_data.TargetName contains "NTLM_SSP"

tags:
  - Account Enumeration
  - Brute Force
```

4. Alert on multiple login attempts by the SYSTEM account within a short period (A-010, A-012, A-014, A-017, A-027,
A-029):

```yaml
rule: Multiple_Login_Attempts_by_SYSTEM_Account
id: 601475e7-c2e2-4372-a41b-0f20171e5659
description: Detects multiple login attempts by the SYSTEM account within a short period
logsource: Security Event Log
detection:
  - sequence:
      - event_data.UserName == "SYSTEM"
      - event_data.LogonType == 2 or event_data.LogonType == 10 or event_data.LogonType == 11 or event_data.LogonType
== 12
      - event_data.SubjectLogonId == 4294967295
      - within: 5 minutes
      - event_data.EventID == 4624
      - event_data.EventID == 4634

tags:
  - Account Enumeration
  - Privileged Accounts
```
