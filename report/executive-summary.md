# Executive Summary — Active Directory Penetration Test (Lab Simulation)

| Field | Detail |
|---|---|
| Environment | TryHackMe — Forward Room (Simulated Internal AD Assessment) |
| Scope | Windows Server 2019 Domain Controller — `CTF.LOCAL` |
| Initial Access | Low-privileged domain user `j.smith` |
| Final Access | Domain Administrator — `Administrator` on `DC01` |
| Vulnerabilities Exploited | 0 CVEs — misconfigurations only |
| Assessment Duration | Lab exercise |

---

## Summary

Starting from a single low-privileged domain user credential (`j.smith:JSmith@IT2024`), the simulated assessment achieved full Domain Administrator access through a chain of **five interconnected misconfigurations** — none of which required exploiting a software vulnerability or CVE.

The attack path demonstrates that **misconfiguration, not missing patches**, is the primary risk in modern Active Directory environments.

### Attack Chain (TL;DR)

```
j.smith (low privilege)
    ↓  KeePass credential extraction
t.jones
    ↓  Password reuse
r.williams
    ↓  MachineAccountQuota = 10
HERMESMED$ (rogue computer account)
    ↓  RBCD → S4U → Pass-the-Ticket
Administrator (Domain Admin) ✓
```

---

## Critical Findings

### Finding 1 — Password Stored in Accessible KeePass Database
**Severity:** High · **CVSS:** 8.1

A KeePass database (`Database.kdbx`) was stored in `C:\Users\j.smith\Documents\`, accessible to the initial foothold user. The database contained credentials for `t.jones` with the password `Helpdesk01!`.

**Impact:** Direct access to a second domain account without brute force, cracking, or additional enumeration.

**Recommendation:**
- Store credential databases in user-specific, ACL-restricted locations
- Prefer enterprise password vaults (CyberArk, HashiCorp Vault) for shared credentials
- Audit filesystem permissions regularly for credential artifacts

---

### Finding 2 — Password Reuse Across Domain Accounts
**Severity:** High · **CVSS:** 8.8

The password `Helpdesk01!` was valid for both `t.jones` and `r.williams`, enabling lateral movement without any additional exploitation.

**Impact:** One extracted credential granted access to multiple accounts, each with different privilege levels.

**Recommendation:**
- Enforce unique passwords via Fine-Grained Password Policies (FGPP)
- Implement Privileged Access Management (PAM) with password rotation
- Conduct regular password spray testing to identify reuse

---

### Finding 3 — MachineAccountQuota Allows Rogue Computer Object Creation
**Severity:** High · **CVSS:** 8.8

`ms-DS-MachineAccountQuota` was set to the default value of **10**, permitting any authenticated domain user to create computer accounts. This directly enabled the RBCD attack chain.

**Impact:** Attacker created `HERMESMED$` as a controlled machine account with a known password, enabling Kerberos S4U impersonation of Administrator.

**Remediation:**
```powershell
Set-ADDomain -Identity CTF -Replace @{"ms-DS-MachineAccountQuota"="0"}
```

**Recommendation:** Set to `0`. Only designated provisioning accounts should have the right to join computers.

---

### Finding 4 — No Alerting on Delegation Attribute Changes
**Severity:** Medium · **CVSS:** 6.5

The `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on `DC01$` was modified without triggering any alert. This attribute change is the centrepiece of the RBCD attack.

**Impact:** Attacker configured delegation silently. No detection until SMB access was achieved as Administrator.

**Recommendation:**
- Enable auditing on Event ID 5136 for delegation attribute changes
- Create SIEM alert for any write to `msDS-AllowedToActOnBehalfOfOtherIdentity`
- Alert on Event ID 4741 (computer account creation) from non-admin users

---

## Remediation Priority

| Priority | Finding | Effort | Detection |
|---|---|---|---|
| 🔴 Critical | Set MachineAccountQuota to 0 | Low — single AD attribute | Event 4741 |
| 🔴 Critical | Enforce unique passwords for help desk accounts | Medium — PAM implementation | Event 4624 |
| 🟠 High | Restrict KeePass database access with file ACLs | Low | File audit |
| 🟠 High | Alert on Event ID 5136 (delegation changes) | Medium — SIEM rule | Event 5136 |
| 🟡 Medium | Alert on Event ID 4741 from non-admin users | Low — SIEM rule | Event 4741 |
| 🟡 Medium | Mark Administrator as "sensitive, cannot be delegated" | Low — AD flag | Event 4769 |

---

## Key Takeaways

1. **Password reuse is the #1 enabler** — it turned a KeePass extraction into lateral movement to a privileged account
2. **Default settings are dangerous** — `MachineAccountQuota = 10` is a legacy default that enables RBCD attacks
3. **Credential storage discipline matters** — unsecured KeePass databases on shared filesystems are a common finding
4. **Alerting gaps allow silent exploitation** — the RBCD attribute write generated Event 5136, but nobody was watching
5. **No CVEs required** — all findings are configuration weaknesses, not software vulnerabilities

---

## References

- [MS-DS-MachineAccountQuota documentation](https://learn.microsoft.com/en-us/windows/win32/adschema/a-ms-ds-machineaccountquota)
- [RBCD Abuse — shenaniganslabs.io](https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html)
- [MITRE ATT&CK — Active Directory](https://attack.mitre.org/tactics/TA0006/)

---

> **Assessment conducted by:** Insiyah · SOC Analysis & Threat Detection  
> **Lab platform:** TryHackMe — Forward Room
