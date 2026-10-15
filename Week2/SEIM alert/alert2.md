 Alert Summary:
The alert SOC176 - RDP Brute Force Detected was triggered due to multiple (5) unsuccessful RDP login attempts by the
source IP address 18.218.132.237 within a 5-minute period, targeting the destination host Olivia (IP address
172.16.17.66) and user account Olivia.

Triggering Evidence:
The RDP login failures are logged events with EventID 126, which were recorded on 2023-03-08T10:32:36+03:00.

Original Alert Severity:
The original alert severity is Medium, as per the provided difficulty level of 'Easy' and the MITRE ATT&CK technique
T1078, which denotes a brute force attack.

Independent Severity Assessment and Rationale:
Given the multiple failed login attempts within a short period, this event can potentially be an attempt to gain
unauthorized access to the RDP server. However, without additional context or information about successful login
attempts, password policies, or the specific user's account permissions, the severity is assessed as Low to Medium.

Confirmed Facts:
- 5 unsuccessful RDP login attempts within 5 minutes by the source IP address 18.218.132.237 targeting the Olivia user
account (IP address 172.16.17.66).
- The firewall allowed the RDP traffic from the source IP address.

Hypotheses:
- The IP address 18.218.132.237 is attempting a brute force attack to gain unauthorized access to the RDP server.
- The IP address 18.218.132.237 may be a bot or script performing automated login attempts.
- The user account Olivia's password may be weak, enabling the attempts to succeed with time.

Confidence:
High confidence that the event represents a brute force attack attempt, as the alert was triggered by the specified
rule and criteria. However, the confidence in the hypotheses is moderate, as additional investigation is required to
confirm them.

Recommended Actions:
1. Investigate the IP address 18.218.132.237 to determine its origin and potential threat level.
2. Review the user account Olivia's password policy and consider strengthening it if necessary.
3. Monitor the destination host (IP address 172.16.17.66) for any successful login attempts or further suspicious
activity.
4. If possible, restrict the number of login attempts for the user account Olivia within a specified time period.

Missing Evidence:
1. Information about the source IP address, such as its known history, threat intelligence data, or association with
any known malicious activity.
2. Successful login attempts or any evidence of unauthorized access to the RDP server.
3. Details about the user account Olivia, including account permissions, last password change, and password complexity
requirements.

Limitations:
- The assessment and recommendations are based on the available information in the alert and associated logs. More
context or data may change the initial analysis.
- The hypotheses are based on common attack patterns and assumptions; further investigation is required to confirm
them.
- The lack of disruptive containment actions is due to the insufficient evidence for an active attack.