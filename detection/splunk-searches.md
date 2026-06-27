# Splunk Detection Queries — AD RBCD Lab

## Event ID Reference

| Event ID | Log | Meaning | Attack Phase |
|---|---|---|---|
| 4624 | Security | Successful logon | Lateral movement |
| 4662 | Security | AD object operation | Enumeration |
| 4741 | Security | Computer account created | RBCD — addcomputer |
| 4742 | Security | Computer account changed | RBCD — attribute write |
| 4768 | Security | Kerberos TGT requested | S4U2Self |
| 4769 | Security | Kerberos service ticket requested | Kerberoasting / S4U2Proxy |
| 5136 | Security | AD directory object modified | RBCD attribute write |

---

## Query 1 — New Computer Account Creation

Triggers on `impacket-addcomputer` or any domain join by a non-admin.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4741
| eval AccountCreated=mvindex(Account_Name,1)
| eval CreatedBy=mvindex(Account_Name,0)
| where NOT match(CreatedBy, "(?i)(system|administrator|\$$)")
| table _time, CreatedBy, AccountCreated, ComputerName, host
| sort -_time
```

**Use case:** Detect rogue machine accounts. Alert if `CreatedBy` is not a trusted provisioning account.

---

## Query 2 — RBCD Attribute Write

Detects `msDS-AllowedToActOnBehalfOfOtherIdentity` being set on any computer object — the centrepiece of the RBCD attack.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=5136
| search AttributeLDAPDisplayName="msDS-AllowedToActOnBehalfOfOtherIdentity"
| table _time, SubjectUserName, ObjectDN, AttributeValue, OperationType
| sort -_time
```

**Use case:** Any write to this attribute outside scheduled maintenance is suspicious.

---

## Query 3 — Kerberoasting Detection

RC4 encrypted TGS requests indicate potential Kerberoasting or S4U abuse.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769
| search TicketEncryptionType="0x17"
| where NOT match(ServiceName, "\$$")
| stats count by AccountName, ServiceName, ClientAddress
| where count > 3
| sort -count
```

**Use case:** High volume of RC4 ticket requests from one source = roasting attempt.

---

## Query 4 — Kerberos Logon Anomaly (Pass-the-Ticket)

Kerberos network logons for Administrator from unusual hosts.

```spl
index=wineventlog sourcetype="WinEventLog:Security" EventCode=4624
  LogonType=3 AuthenticationPackageName=Kerberos
| search TargetUserName="Administrator"
| table _time, TargetUserName, WorkstationName, IpAddress, LogonType
| sort -_time
```

**Use case:** Administrator should almost never authenticate via network logon. Every hit warrants investigation.

---

## Query 5 — Full RBCD Attack Timeline Correlation

Correlates the full attack chain into one timeline.

```spl
index=wineventlog sourcetype="WinEventLog:Security"
  (EventCode=4741 OR EventCode=5136 OR EventCode=4769 OR EventCode=4624)
| eval phase=case(
    EventCode==4741, "1-Computer Account Created",
    EventCode==5136, "2-Delegation Attribute Modified",
    EventCode==4769, "3-Kerberos Ticket Requested",
    EventCode==4624, "4-Network Logon"
  )
| table _time, phase, EventCode, Account_Name, ComputerName
| sort _time
```

**Use case:** If you see events 4741 → 5136 → 4769 → 4624 in sequence from the same source, you are likely witnessing an RBCD attack in progress.

---

## Dashboard Panel Ideas

1. **Computer Account Creation Rate** — bar chart by day, baseline vs anomaly
2. **Delegation Attribute Changes** — table with user, object, timestamp
3. **RC4 TGS Requests** — volume over time with source IP
4. **Kerberos Logons for Privileged Accounts** — heat map by hour and source

---

## MITRE ATT&CK Cross-Reference

| Query | Detects | ATT&CK ID |
|---|---|---|
| Q1 — Computer Account Created | Account creation | T1136.001 |
| Q2 — RBCD Attribute Write | Policy modification | T1484 |
| Q3 — Kerberoasting | Steal/forge tickets | T1558.003 |
| Q4 — Pass-the-Ticket | Use alternate auth material | T1550.003 |
| Q5 — Timeline Correlation | Full chain | Multi-technique |

---

## False Positives & Tuning

| Query | Common FP | Tuning |
|---|---|---|
| Q1 (4741) | Automated provisioning tools | Whitelist known provisioning accounts |
| Q2 (5136) | Scheduled delegation changes | Maintenance windows, change control IDs |
| Q3 (RC4 TGS) | Legacy services using RC4 | Whitelist known legacy SPNs |
| Q4 (4624 Admin) | Legitimate admin remote access | Compare with PAM/session manager logs |
