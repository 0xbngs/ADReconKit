# ADReconKit

Short Cobalt Strike beacon commands for Active Directory reconnaissance over LDAP using native **ADSI** (`[ADSI]` + `[ADSISearcher]`).

Example:

```
beacon> adrecon_asrep 192.168.56.11 north.sevenkingdoms.local
[+] host called home, sent: 2415 bytes
[+] received output:
[*] ADReconKit - AS-REP Roasting
[+] catelyn.stark (vuln AS-REP Roasting)
[+] brandon.stark (vuln AS-REP Roasting)
[*] Total: 2 object(s)
```

Built for authorized red team training (GOAD / sevenkingdoms lab style).

## MITRE ATT&CK

| ID | Technique | Command |
|----|-----------|---------|
| **T1558.004** | Steal or Forge Kerberos Tickets: AS-REP Roasting | `adrecon_asrep` |
| **T1558.003** | Steal or Forge Kerberos Tickets: Kerberoasting | `adrecon_kerberoast` |
| **T1087.002** | Account Discovery: Domain Account | `adrecon_users`, `adrecon_userdesc` |
| **T1018** | Remote System Discovery | `adrecon_computers`, `adrecon_dcs` |
| **T1649** | Steal or Forge Authentication Certificates | `adrecon_esc1` |
| **T1201** | Password Policy Discovery | `adrecon_pwnever`, `adrecon_weakpwd` |
| **T1069.002** | Permission Groups Discovery: Domain Groups | `adrecon_admins` |
| **T1615** | Group Policy Discovery | `adrecon_gpo` |
| **T1482** | Domain Trust Discovery | `adrecon_trusts` |
| **T1016** | System Network Configuration Discovery | `adrecon_sites` |

## Requirements

- Cobalt Strike 4.x -> The system used for testing is Cobalt 4.9

## Installation

1. Cobalt Strike → **Script Manager** → **Load**
2. Select `ADReconKit/adrecon.cna`
3. If the script was already loaded, **Unload** then **Load** again

No `make` step is required for the beacon commands.

## Parameters

Every command takes two arguments:

| Parameter | Description |
|-----------|-------------|
| **IP** | Domain Controller IP or hostname |
| **DomainFQDN** | Domain FQDN, converted to LDAP DN automatically (`north.sevenkingdoms.local` → `DC=north,DC=sevenkingdoms,DC=local`) |

## Command index

```
adrecon_asrep      <IP> <DomainFQDN>   # DONT_REQ_PREAUTH (4194304)
adrecon_kerberoast <IP> <DomainFQDN>   # users with SPN, skip krbtgt
adrecon_users      <IP> <DomainFQDN>   # all user sAMAccountName
adrecon_userdesc   <IP> <DomainFQDN>   # user + displayName + description
adrecon_computers  <IP> <DomainFQDN>   # computers / outdated OS
adrecon_esc1       <IP> <DomainFQDN>   # ADCS templates, SAN flag, EKU
adrecon_pwnever    <IP> <DomainFQDN>   # DONT_EXPIRE_PASSWORD (65536)
adrecon_weakpwd    <IP> <DomainFQDN>   # PASSWD_NOTREQD (32) + disabled (2)
adrecon_admins     <IP> <DomainFQDN>   # Domain Admins + privileged groups
adrecon_gpo        <IP> <DomainFQDN>   # GPO name / GUID / SYSVOL path
adrecon_dcs        <IP> <DomainFQDN>   # DC (8192) / writable (516) / RODC (521)
adrecon_trusts     <IP> <DomainFQDN>   # inbound / outbound / bidirectional
adrecon_sites      <IP> <DomainFQDN>   # subnets + sites (Configuration NC)
adrecon_all        <IP> <DomainFQDN>   # run every module
```

GOAD / sevenkingdoms examples:

```
adrecon_asrep      192.168.56.11 north.sevenkingdoms.local
adrecon_kerberoast 192.168.56.11 north.sevenkingdoms.local
adrecon_users      192.168.56.11 north.sevenkingdoms.local
adrecon_userdesc   192.168.56.11 north.sevenkingdoms.local
adrecon_computers  192.168.56.11 north.sevenkingdoms.local
adrecon_esc1       192.168.56.10 sevenkingdoms.local
adrecon_pwnever    192.168.56.11 north.sevenkingdoms.local
adrecon_weakpwd    192.168.56.11 north.sevenkingdoms.local
adrecon_admins     192.168.56.11 north.sevenkingdoms.local
adrecon_gpo        192.168.56.11 north.sevenkingdoms.local
adrecon_dcs        192.168.56.11 north.sevenkingdoms.local
adrecon_trusts     192.168.56.11 north.sevenkingdoms.local
adrecon_sites      192.168.56.10 sevenkingdoms.local
adrecon_all        192.168.56.11 north.sevenkingdoms.local
```

`adrecon_esc1` and `adrecon_sites` query the Configuration NC (forest). In GOAD that is usually `192.168.56.10` / `sevenkingdoms.local`.

---

## 1. `adrecon_asrep` — AS-REP Roasting

Find user accounts that do not require Kerberos pre-authentication (`DONT_REQ_PREAUTH`). Those accounts can be AS-REP roasted.

```
adrecon_asrep 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filter**

```
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))
```

`1.2.840.113556.1.4.803` is bitwise AND. `4194304` is `0x400000` (`DONT_REQ_PREAUTH`).

**Bind**

```
LDAP://192.168.56.11/DC=north,DC=sevenkingdoms,DC=local
```

**Output**

```
[*] ADReconKit - AS-REP Roasting
[*] Target : 192.168.56.11
[*] Domain : north.sevenkingdoms.local
[*] DN     : DC=north,DC=sevenkingdoms,DC=local
[+] catelyn.stark (vuln AS-REP Roasting)
[+] brandon.stark (vuln AS-REP Roasting)
[*] Total: 2 object(s)
```

Each printed `sAMAccountName` is an AS-REP roast candidate.

---

## 2. `adrecon_kerberoast` — Kerberoasting

Find user accounts with a `servicePrincipalName`, excluding `krbtgt`. Those accounts can be Kerberoasted.

```
adrecon_kerberoast 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filter**

```
(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(cn=krbtgt)))
```

**Output**

```
[*] ADReconKit - Kerberoasting
[+] sqlsvc (vuln KerbeRoasting)
[+]    SPN: MSSQLSvc/castelnoir.north.sevenkingdoms.local:1433
[*] Total: 1 object(s)
```

---

## 3. `adrecon_users` — Enumerate users

List every domain user `sAMAccountName`.

```
adrecon_users 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filter**

```
(&(objectCategory=person)(objectClass=user))
```

**Output**

```
[*] ADReconKit - Enumerate Users
[+] administrator
[+] guest
[+] catelyn.stark
[+] brandon.stark
[*] Total: N object(s)
```

---

## 4. `adrecon_userdesc` — Users with name and description

Same user set as `adrecon_users`, plus `displayName` and `description` (often contains passwords or hints in labs).

```
adrecon_userdesc 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filter**

```
(&(objectCategory=person)(objectClass=user))
```

**Attributes:** `sAMAccountName`, `displayName`, `description`

**Output**

```
[*] ADReconKit - Users with Description
[+] User        : catelyn.stark
[+]   Name      : Catelyn Stark
[+]   Description: ...
[*] Total: N object(s)
```

---

## 5. `adrecon_computers` — Computers / outdated OS

Enumerate computer objects and flag old OS strings (XP, Vista, 7, 8, 2000, NT, Server 2003/2008/2012).

```
adrecon_computers 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filter**

```
(objectClass=computer)
```

**Attributes:** `sAMAccountName`, `operatingSystem`, `operatingSystemVersion`

**Output**

```
[*] ADReconKit - Computers / Outdated OS
[+] CASTELNOIR$  OS=Windows Server 2019  Ver=10.0 (17763)
[+] OLDPC$  OS=Windows 7 Professional  Ver=6.1 (7601)  [OUTDATED / HIGH RISK]
[*] Total: N object(s)
```

---

## 6. `adrecon_esc1` — ADCS ESC1 (SAN / EKU)

Enumerate certificate templates. Reads `configurationNamingContext` from rootDSE, then searches:

```
CN=Certificate Templates,CN=Public Key Services,CN=Services,<configDN>
```

```
adrecon_esc1 192.168.56.10 sevenkingdoms.local
```

**LDAP filter**

```
(objectClass=pKICertificateTemplate)
```

**Attributes:** `cn`, `msPKI-Certificate-Name-Flag`, `pKIExtendedKeyUsage`, `msPKI-Enrollment-Flag`

**Logic**

- `SAN_Suppliable` = `msPKI-Certificate-Name-Flag` bit `0x1` (`CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT`)
- Client-auth EKU = `1.3.6.1.5.5.7.3.2` (Client Authentication), `1.3.6.1.4.1.311.20.2.2` (Smart Card Logon), `2.5.29.37.0` (Any Purpose), or empty EKU
- `ESC1 : LIKELY VULNERABLE` when SAN is set **and** the EKU allows authentication

**Output (GOAD excerpt)**

```
[*] ADReconKit - ADCS ESC1 (SAN / EKU)
[*] Config DN : CN=Configuration,DC=sevenkingdoms,DC=local
[*] DN     : CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=sevenkingdoms,DC=local
[+] Template : User
[+]   SAN    : NO
[+]   EKU    : 1.3.6.1.4.1.311.10.3.4, 1.3.6.1.5.5.7.3.4, 1.3.6.1.5.5.7.3.2
[+]   ESC1   : No
[+] Template : CA
[+]   SAN    : YES (Vulnerable SAN)
[+]   EKU    : (none / Any Purpose)
[+]   ESC1   : LIKELY VULNERABLE
[+] Template : ESC1
[+]   SAN    : YES (Vulnerable SAN)
[+]   EKU    : 1.3.6.1.5.5.7.3.2
[+]   ESC1   : LIKELY VULNERABLE
[*] Total: 34 object(s)
```

In the sevenkingdoms lab the custom `ESC1` template is the intended finding. Built-in templates such as `CA` / `SubCA` / `CrossCA` also match the SAN + empty-EKU rule.

---

## 7. `adrecon_pwnever` — Password never expires

Find users with `DONT_EXPIRE_PASSWORD`.

```
adrecon_pwnever 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filter**

```
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))
```

`65536` is `0x10000` (`DONT_EXPIRE_PASSWORD`).

**Output**

```
[*] ADReconKit - Password Never Expires
[+] sqlsvc    Name: SQL Service
[*] Total: N object(s)
```

---

## 8. `adrecon_weakpwd` — PASSWD_NOTREQD + disabled

Two searches:

1. `PASSWD_NOTREQD` (`32` / `0x20`) — password not required (blank / weak / default possible)
2. `ACCOUNTDISABLE` (`2` / `0x2`) — disabled accounts

```
adrecon_weakpwd 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filters**

```
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))
(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))
```

**Output**

```
[*] ADReconKit - PASSWD_NOTREQD (blank / weak / default possible)
[+] someuser    Name: Some User
[*] Total: N object(s)

[*] ADReconKit - Disabled Accounts
[+] DisabledUser: guest    Description: ...
[*] Total: N object(s)
```

---

## 9. `adrecon_admins` — Privileged groups

Enumerate members of privileged groups via `memberOf` (direct membership).

```
adrecon_admins 192.168.56.11 north.sevenkingdoms.local
```

**Groups**

| Group | DN |
|-------|----|
| Domain Admins | `CN=Domain Admins,CN=Users,<domainDN>` |
| Administrators (Builtin) | `CN=Administrators,CN=Builtin,<domainDN>` |
| Account Operators | `CN=Account Operators,CN=Builtin,<domainDN>` |
| Backup Operators | `CN=Backup Operators,CN=Builtin,<domainDN>` |
| Server Operators | `CN=Server Operators,CN=Builtin,<domainDN>` |
| Print Operators | `CN=Print Operators,CN=Builtin,<domainDN>` |
| DnsAdmins | `CN=DnsAdmins,CN=Users,<domainDN>` |

**LDAP filter (example)**

```
(&(objectCategory=person)(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=north,DC=sevenkingdoms,DC=local))
```

**Output**

```
[*] ADReconKit - Domain Admins
[+] administrator    Name: Administrator
[*] Total: N object(s)
```

This is a **direct** `memberOf` match (same as the course ADSI one-liner). Nested group members are not expanded.

---

## 10. `adrecon_gpo` — Group Policy Objects

Enumerate GPOs under `CN=Policies,CN=System,<domainDN>`.

```
adrecon_gpo 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filter**

```
(objectClass=groupPolicyContainer)
```

**Attributes:** `displayName`, `cn` (GUID), `gPCFileSysPath` (SYSVOL)

**Bind**

```
LDAP://192.168.56.11/CN=Policies,CN=System,DC=north,DC=sevenkingdoms,DC=local
```

**Output**

```
[*] ADReconKit - GPO Locations
[+] GPOName    : Default Domain Policy
[+]   GUID     : {31B2F340-016D-11D2-945F-00C04FB984F9}
[+]   SYSVOL   : \\north.sevenkingdoms.local\sysvol\north.sevenkingdoms.local\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}
[*] Total: N object(s)
```

---

## 11. `adrecon_dcs` — Domain Controllers and RODCs

Three searches:

| Check | Filter |
|-------|--------|
| All DCs | `userAccountControl` bit `SERVER_TRUST_ACCOUNT` (`8192` / `0x2000`) |
| Writable DCs | `primaryGroupID=516` (Domain Controllers) |
| RODCs | `primaryGroupID=521` (Read-Only Domain Controllers) |

Also flags `PARTIAL_SECRETS_ACCOUNT` (`0x04000000`) as `[RODC]` on the UAC search.

```
adrecon_dcs 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filters**

```
(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))
(&(objectCategory=computer)(primaryGroupID=516))
(&(objectCategory=computer)(primaryGroupID=521))
```

**Output**

```
[*] ADReconKit - Domain Controllers (UAC SERVER_TRUST_ACCOUNT=8192)
[+] DCName: WINTERFELL$    OS: Windows Server 2019 Standard
[*] Total: 1 object(s)
```

---

## 12. `adrecon_trusts` — Domain trust mapping

Enumerate `trustedDomain` objects under `CN=System,<domainDN>`.

```
adrecon_trusts 192.168.56.11 north.sevenkingdoms.local
```

**LDAP filter**

```
(objectClass=trustedDomain)
```

**Attributes:** `cn`, `trustPartner`, `trustDirection`, `trustType`, `trustAttributes`

**Bind**

```
LDAP://192.168.56.11/CN=System,DC=north,DC=sevenkingdoms,DC=local
```

**trustDirection**

| Value | Meaning |
|-------|---------|
| **1 Inbound** | Target trusts us |
| **2 Outbound** | We trust target (pivot candidate) |
| **3 Bidirectional** | Both ways; parent-child ExtraSID / SID History is in scope |

**trustType**

| Value | Meaning |
|-------|---------|
| 1 | Downlevel (NT) |
| 2 | Uplevel (AD) |
| 3 | MIT |
| 4 | DCE |

**Output**

```
[*] ADReconKit - Domain Trust Mapping
[+] TargetDomain  : sevenkingdoms.local
[+]   Direction   : Bidirectional (3)
[+]   Type        : Uplevel (AD) (2)
[+]   Attributes  : 0x00000000
[+]   Note        : Bidirectional - parent-child ExtraSID / SID History possible
[*] Total: 1 object(s)
```

---

## 13. `adrecon_sites` — Subnet and site topology

Reads `configurationNamingContext` from rootDSE, then searches:

```
CN=Subnets,CN=Sites,<configDN>
```

```
adrecon_sites 192.168.56.10 sevenkingdoms.local
```

**LDAP filter**

```
(objectClass=subnet)
```

**Attributes:** `cn` (subnet), `siteObject`, `description`

Site name is the first RDN of `siteObject` (`CN=Default-First-Site-Name,...` → `Default-First-Site-Name`). Empty `siteObject` prints `Unassigned`.

**Output**

```
[*] ADReconKit - Subnet & Site Topology
[*] Config DN : CN=Configuration,DC=sevenkingdoms,DC=local
[*] DN     : CN=Subnets,CN=Sites,CN=Configuration,DC=sevenkingdoms,DC=local
[+] Subnet      : 192.168.56.0/24
[+]   Site      : Default-First-Site-Name
[+]   Description: ...
[*] Total: N object(s)
```

---

## `adrecon_all`

Runs every module above against the given IP and domain (ESC1 and sites still resolve Configuration NC from that DC's rootDSE).

```
adrecon_all 192.168.56.11 north.sevenkingdoms.local
```

This fires many LDAP searches. Use a single module first when you only need one check.

---

## How it works

1. Convert `DomainFQDN` → LDAP DN (`north.sevenkingdoms.local` → `DC=north,DC=sevenkingdoms,DC=local`)
2. Run Beacon `powershell` with `[ADSI]('LDAP://<IP>/<DN>')` and `[ADSISearcher]` (same filters as `BangunBof2.txt`)
3. Command is sent as `-EncodedCommand` so the console does not print the full one-liner (`Tasked beacon to run: ...`)
4. ESC1 / sites read `configurationNamingContext` from rootDSE, then bind under the Configuration NC
5. Results are printed with the lab labels (`(vuln AS-REP Roasting)`, `LIKELY VULNERABLE`, etc.)

LDAP matching rule `1.2.840.113556.1.4.803` is bitwise AND against `userAccountControl`.

The job is fork&run (`powershell.exe` in a sacrificial process). The beacon process stays up if the query fails.

## OPSEC

| Concern | Guidance |
|---------|----------|
| **powershell.exe** | Spawned as a Beacon post-ex job (same family as the `powershell` command) |
| **Command line** | Script is `-EncodedCommand` (UTF-16LE Base64); console does not echo the LDAP one-liner |
| **LDAP volume** | `adrecon_all` and `adrecon_users` dump many objects; start with a targeted module |
| **MDI / 4662** | Unusual LDAP filters (`servicePrincipalName=*`, UAC `4194304`) can alert |
| **Credentials** | Uses the beacon token; `make_token` / `steal_token` if the host is not domain-joined |

## Detection

| Source | Details |
|--------|---------|
| **Windows 4662** | Directory Service Access on user/computer/template objects |
| **MDI** | LDAP search / reconnaissance alerts |
| **Network** | LDAP 389 from a workstation to a DC with recon filters |
| **Sysmon 1 / 10** | `powershell.exe -EncodedCommand` spawned from the Beacon job |
| **Sysmon 22** | DNS query for the DC if a hostname is used instead of an IP |

## Project structure

```
ADReconKit/
├── adrecon.cna           # Aggressor aliases (load this)
├── README.md             # This file
├── adrecon.c             # Optional in-process BOF source (not used by the aliases)
├── beacon.h
├── bofdefs.h
├── adsi_interfaces.h
├── base.c
└── Makefile
```

Load **`adrecon.cna`** only. The C BOF files are leftover from the in-process attempt; the aliases use ADSI via Beacon `powershell`.

## References

- [MITRE ATT&CK T1558](https://attack.mitre.org/techniques/T1558/)
- [Outflank — AD recon with ADSI](https://www.outflank.nl/blog/2019/10/20/red-team-tactics-active-directory-recon-using-adsi-and-reflective-dlls/)
- [SpecterOps Certified Pre-Owned (ADCS)](https://posts.specterops.io/certified-pre-owned-d95910965cd2)
- Course notes: `BangunBof2.txt`

## Disclaimer

For authorized security testing, adversary emulation, and red team education only. Unauthorized use is illegal.

## License

MIT
