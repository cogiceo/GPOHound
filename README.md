
# GPOHound

`GPOHound` is a tool for dumping and analysing Group Policy Objects (GPOs) extracted from the SYSVOL share. 

It provides a structured, formalized format to help uncover misconfigurations, insecure settings, and privilege escalation paths in Active Directory environments.

The tool integrates with BloodHound's Neo4j database, using it as an LDAP-like source for Active Directory information while also enriching it by adding new relationships (edges) and node properties based on the analysis.

## Features

### Dump

- [x] Dumps GPOs in a structured JSON or tree format  
  
- [x] Handles multiple domains  

- [x] Resolves GPO names with GPO GUIDs  

- [x] Filters output by GPO files, GPO GUIDs, and domains  

- [x] Searches in key/value pairs using regex  

### Analysis

- [x] Groups settings by impacted object (e.g., Local Groups, Registry)  

- [x] Detects members added to local privileged groups  

- [x] Detects insecure registry settings, stored credentials, and privilege rights  

- [x] Supports decrypting VNC credentials and GPP passwords  

- [x] Finds domains, containers, and OUs affected by GPOs  

- [x] Gets GPOs applied to a specific user, computer, OU, container, or domain  

- [x] Enriches BloodHound data with relationships and properties  


## Installation

### Install with pip

```
git clone "https://github.com/cogiceo/GPOHound"
cd GPOHound
pip install .
```

### Install with pipx

```
pipx install "git+https://github.com/cogiceo/GPOHound"
```


### Setup APOC for Neo4j

You need to setup Neo4j APOC for BloodHound data enrichment:

- If you're using the standard Neo4j installation, you can enable APOC by copying the APOC `jar` file to the plugin folder and then restart Neo4j:

  ```bash
  cp /var/lib/neo4j/labs/apoc-* /var/lib/neo4j/plugins/
  neo4j restart
  ```

- If you are installing Neo4j with "Docker Compose", add the environment variable `NEO4J_PLUGINS=["apoc"]`:

  ```yaml
  neo4j:
    image: neo4j:latest
    environment:
      - NEO4J_PLUGINS=["apoc"]
  ```

> For more details or alternate installation methods, refer to the official [APOC Documentation](https://neo4j.com/docs/apoc/current/installation/).

### Add BloodHound Queries

To visualize the relationships and properties added by `GPOHound`, you can import the custom queries from the `customqueries.json` file into BloodHound. By default, this file is located at `~/.config/bloodhound/customqueries.json`.

## Prerequisites

### Dumping SYSVOL

Start by downloading the `SYSVOL` contents from the domain controller.

- Download the full `SYSVOL`:

  ```bash
  gpohound sysvol --dc $DC_HOST -d $DOMAIN -u $USER -p $PASSWORD 
  ```

- Download only the GPOs:

  ```bash
  gpohound sysvol --dc $DC_HOST -d $DOMAIN -u $USER -p $PASSWORD --gpos
  ```

- Download with exclusions:

  ```bash
  gpohound sysvol --dc $DC_HOST -u $USER -p $PASSWORD --exclude '/Policydefinitions/','/scripts/' --max-size 100
  ```

### Dumping LDAP

Retrieve all required data from LDAP : 

```bash
gpohound ldap --dc $DC_HOST -d $DOMAIN -u $USER -p $PASSWORD
```

### BloodHound

For BloodHound data enrichment, you must collect BloodHound data using a collector such as `bloodhound.py` or `SharpHound.exe` and import the gathered data into the BloodHound interface.

## Usage

Sample GPOHound files are available in `example.zip`. Extract them with `unzip example.zip`.

See [CONFIG.md](./CONFIG.md) for instructions on customizing default values and configurations.

```bash
gpohound --neo4j-user $USER --neo4j-pass $PASS dump
gpohound --neo4j-user $USER --neo4j-pass $PASS analysis
```

### Parse

```bash
gpohound parse "gpos/sysvols/$DOMAIN/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol"
```

### Dump

```bash
gpohound dump
gpohound dump --list
gpohound dump --guid 31B2F340-016D-11D2-945F-00C04FB984F9
gpohound dump --policies scripts psscripts
gpohound dump --search 'VNC.*Server' --show
```

### Analysis

```bash
gpohound analysis
gpohound analysis --affected
gpohound analysis --trustee 'SRV01.SEVENKINGDOMS.LOCAL'
gpohound analysis --trustee 'SRV01.SEVENKINGDOMS.LOCAL' --list
gpohound analysis --trustee 'SRV01.SEVENKINGDOMS.LOCAL' --dump
gpohound analysis --enrich
gpohound analysis --enrich-ce
```


## Current analysis and enrichment


> [!IMPORTANT] 
> - Conditions like security filters, WMI filters, and item-level targeting are not interpreted.
> - GPO conflicts are not simulated, to avoid missing valid settings.

### Local Groups

- Detection of users assigned to privileged local groups during logon

- Detection of renamed built-in privileged local groups.

- Detection of trustees added to privileged local groups using "Preference Process Variables" (e.g., %ComputerName%, %DomainName%)

- Detection of abusable trustees using `sAMAccountName` hijacking

- Detection of any trustees added to privileged local groups:

  | Group                          | Edge         |
  |--------------------------------|--------------|
  | Administrators                 | `AdminTo`    |
  | Remote Desktop Users           | `CanRDP`     |
  | Distributed COM Users          | `ExecuteDCOM`|
  | Remote Management Users        | `CanPSRemote`|
  | Backup Operators               | `CanPrivEsc` |
  | Print Operators                | `CanPrivEsc` |
  | Network Configuration Operators| `CanPrivEsc` |

### Registry

| Analysis                                                                 | Property                 |
|--------------------------------------------------------------------------|---------------------------|
| "Everyone" group includes "Anonymous Logon"                              | —                         |
| SMB server session signing is not enabled                                | `smbSigningEnabled: false`|
| SMB server session signing is not required                               | `smbSigningRequired: false`|
| NTLMv1 authentication is supported                                       | `NTLMv1Support: true`     |
| Windows automatic logon default password                                 | —                         |
| VNC credentials (Generic: RealVNC, TightVNC, TigerVNC, etc.)             | `*VNC*PASS*` (various)  |
| FileZilla stored passwords                                               | —                         |
| PuTTY proxy password                                                     | —                         |
| TeamViewer stored credentials                                            | —                         |
| WinSCP saved sessions                                                    | —                         |
| Picasa stored password                                                   | —                         |

### Privileged Rights

Default privileged trustees, as well as service accounts with SIDs starting with `S-1-5-8`, are excluded from analysis.

| Privilege                       | Description                                            | Edge         |
|---------------------------------|--------------------------------------------------------|--------------|
| SeDebugPrivilege                | Allows user to debug and interact with any process     | `CanPrivEsc` |
| SeBackupPrivilege               | Grants access to sensitive files                       | `CanPrivEsc` |
| SeRestorePrivilege              | Bypasses object permissions during restore             | `CanPrivEsc` |
| SeAssignPrimaryTokenPrivilege   | Enables token impersonation for SYSTEM escalation      | `CanPrivEsc` |
| SeImpersonatePrivilege          | Allows creation of process under another user’s context| `CanPrivEsc` |
| SeTakeOwnershipPrivilege        | Lets users take ownership of system objects            | `CanPrivEsc` |
| SeTcbPrivilege                  | Grants the ability to act as part of the OS            | `CanPrivEsc` |
| SeCreateTokenPrivilege          | Permits creation of authentication tokens              | `CanPrivEsc` |
| SeLoadDriverPrivilege           | Authorizes driver loading/unloading                    | `CanPrivEsc` |
| SeManageVolumePrivilege         | Grants volume or disk management privileges            | `CanPrivEsc` |

# Improvement

- [x] Improve logging
- [x] Integrate LDAP
- [x] Integrate SMB
- [ ] Parse remaining extensions 
- [ ] Web interface
- [ ] Highlight potential conflicts between GPOs


## GPO Documentation

### SYSVOL and LDAP

- [x] [\[MS-GPAC\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPAC/) Audit Configuration Extension
- [x] [\[MS-GPCAP\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPCAP/) Central Access Policies Protocol Extension
- [x] [\[MS-GPEF\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPEF/) Encrypting File System Extension
- [x] [\[MS-GPFAS\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPFAS/) Firewall and Advanced Security Data Structure
- [x] [\[MS-GPFR\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPFR/) Folder Redirection Protocol Extension
- [ ] [\[MS-GPIE\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPIE/) Internet Explorer Maintenance Extension
- [x] [\[MS-GPNAP\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPNAP/) Network Access Protection (NAP) Extension
- [x] [\[MS-GPNRPT\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPNRPT/) Name Resolution Policy Table (NRPT) Data Extension
- [x] [\[MS-GPOL\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPOL/) Core Protocol
- [x] [\[MS-GPPREF\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPPREF/) Preferences Extension Data Structure
- [x] [\[MS-GPREG\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPREG/) Registry Extension Encoding
- [x] [\[MS-GPSB\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPSB/) Security Protocol Extension
- [x] [\[MS-GPSCR\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPSCR/) Scripts Extension Encoding
- [x] [\[MS-GPSI\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPSI/) Software Installation Protocol Extension


### LDAP Only

- [x] [\[MS-GPDPC\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPDPC/) Deployed Printer Connections Extension
- [ ] [\[MS-GPWL\]](https://learn.microsoft.com/en-us/openspecs/windows_protocols/MS-GPWL/) Wireless/Wired Protocol Extension
