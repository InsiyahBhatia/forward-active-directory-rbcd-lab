# Enumeration Notes — AD RBCD Lab

## Methodology Order

```
Network scan → LDAP → SMB → Credential gathering → Exploitation
```

Running `crackmapexec` or `GetUserSPNs` before completing LDAP enumeration means you may authenticate against services unnecessarily, generating logs before you have a clear picture of the environment.

---

## LDAP Enumeration

### Anonymous Bind Check

```bash
ldapsearch -x -H ldap://10.48.137.121 -s base namingcontexts
```

If this returns data, the domain allows unauthenticated LDAP queries. Document the base DN (e.g., `DC=ctf,DC=local`) before proceeding.

### Authenticated User Dump

```bash
ldapsearch -x -H ldap://10.48.137.121 \
  -D "CTF\j.smith" -w 'JSmith@IT2024' \
  -b "DC=ctf,DC=local" \
  "(objectClass=user)" \
  sAMAccountName memberOf description adminCount
```

### Attributes Worth Noting

| Attribute | Why It Matters |
|---|---|
| `memberOf` | Group membership reveals privilege escalation paths |
| `description` | Admins sometimes store passwords here |
| `adminCount=1` | Protected accounts (AdminSDHolder) — high value |
| `pwdLastSet=0` | Password never set — possible AS-REP roasting |
| `userAccountControl` | Bit flags: disabled, no pre-auth required, etc. |

### MachineAccountQuota Check

```bash
ldapsearch -x -H ldap://10.48.137.121 \
  -D "CTF\r.williams" -w 'Helpdesk01!' \
  -b "DC=ctf,DC=local" \
  "(objectClass=domainDNS)" ms-DS-MachineAccountQuota
```

Value > 0 means any authenticated user can create computer objects — the prerequisite for RBCD abuse.

### RBCD Attribute Verification (after write)

```bash
ldapsearch -x -H ldap://10.48.137.121 \
  -D "CTF\r.williams" -w 'Helpdesk01!' \
  -b "DC=ctf,DC=local" \
  "(sAMAccountName=DC01$)" msDS-AllowedToActOnBehalfOfOtherIdentity
```

If this returns a non-empty value, delegation is configured. If empty, the RBCD write failed.

---

## SMB Enumeration

```bash
# Check signing and OS version
crackmapexec smb 10.48.137.121

# List shares (authenticated)
smbmap -H 10.48.137.121 -u j.smith -p 'JSmith@IT2024'

# Browse a specific share
smbclient //10.48.137.121/Downloads -U 'CTF.LOCAL\j.smith%JSmith@IT2024'

# Recursive file listing
smbmap -H 10.48.137.121 -u j.smith -p 'JSmith@IT2024' -R
```

### What to look for in shares

| Artifact | Description |
|---|---|
| `*.kdbx` | KeePass databases — credential goldmine |
| `Groups.xml` in SYSVOL | GPP password (cPassword) |
| `*.xml`, `*.config` | App configs with hardcoded credentials |
| `*.ps1`, `*.bat` | Scripts with embedded credentials |
| `*.txt`, `*.xlsx` | Admin notes, password lists |

---

## BloodHound Collection

> Not performed in this lab run. Recommended for future assessments.

```bash
# Python-based collector (no agent needed)
bloodhound-python -u j.smith -p 'JSmith@IT2024' \
  -d CTF.LOCAL -ns 10.48.137.121 -c All

# Ingest JSON files into BloodHound
# Query: "Shortest Path to Domain Admin"
```

BloodHound would have visualised the `r.williams → RBCD → DC01$` path immediately.

---

## Lab Findings Summary

| Enumeration Step | Tool | Finding |
|---|---|---|
| Port scan | Nmap | 10 open ports on DC01 |
| Service versions | Nmap -sV | AD services confirmed |
| LDAP base | ldapsearch | DC=ctf,DC=local |
| Users | GetADUsers | 7 users including svc.helpdesk |
| Groups | ldapsearch | r.williams in sysadmin + RDP Users |
| SPNs | GetUserSPNs | svc.helpdesk registered |
| SMB shares | crackmapexec | SYSVOL, NETLOGON, Downloads, C$ |
| MachineAccountQuota | ldapsearch | 10 — vulnerable |
| Privileges | whoami /priv | SeMachineAccountPrivilege present |
