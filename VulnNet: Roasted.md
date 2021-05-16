# Tryhackme (writeup)
## VulnNet: Roasted
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


