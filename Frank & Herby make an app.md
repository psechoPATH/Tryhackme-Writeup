<p align="center">
  <img src="https://codefresh.io/wp-content/uploads/2017/02/Intro-to-Kubernetes-blog-b-2-1024x268.png">
</p>

>## Frank & Herby make an app
### Link: https://tryhackme.com/room/frankandherby

### Tasks
1- 
What port has a webpage frank was able to stand up? 

2- 
What did frank leave exposed on the site? 

3-
user flag

4-
root flag

>### Enumeration:

### Ports Scan:


```
  ~/THM/frank                                                                                                                                       with root@ubuntu
❯ rustscan 10.10.114.171                 
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/root/.config/rustscan/config.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.114.171:22
Open 10.10.114.171:3000
Open 10.10.114.171:10255
Open 10.10.114.171:10259
Open 10.10.114.171:10257
Open 10.10.114.171:10250
Open 10.10.114.171:16443
Open 10.10.114.171:25000
Open 10.10.114.171:31337
Open 10.10.114.171:32000

```

## Nmpa Scan

```
  ~/THM/frank                                                                                                                         took  1m 17s with root@ubuntu
❯ nmap -sV -sC -Pn -n -A -p 22,3000,10255,10259,10257,10250,16443,25000,31337,32000 10.10.114.171 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-03 18:12 CET
Stats: 0:01:12 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 70.00% done; ETC: 18:14 (0:00:30 remaining)
Nmap scan report for 10.10.114.171
Host is up (0.31s latency).

PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 64:79:10:0d:72:67:23:80:4a:1a:35:8e:0b:ec:a1:89 (RSA)
|   256 3b:0e:e7:e9:a5:1a:e4:c5:c7:88:0d:fe:ee:ac:95:65 (ECDSA)
|_  256 d8:a7:16:75:a7:1b:26:5c:a9:2e:3f:ac:c0:ed:da:5c (ED25519)
3000/tcp  open  ppp?
| fingerprint-strings: 
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     Content-Security-Policy: default-src 'self' ; connect-src *; font-src 'self' data:; frame-src *; img-src * data:; media-src * data:; script-src 'self' 'unsafe-eval' ; style-src 'self' 'unsafe-inline' 
|     X-Instance-ID: six3DL4bMKTc7kTEG
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Wed, 03 Nov 2021 17:12:32 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|     <meta name="distribution" content
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-XSS-Protection: 1
|     X-Content-Type-Options: nosniff
|     X-Frame-Options: sameorigin
|     Content-Security-Policy: default-src 'self' ; connect-src *; font-src 'self' data:; frame-src *; img-src * data:; media-src * data:; script-src 'self' 'unsafe-eval' ; style-src 'self' 'unsafe-inline' 
|     X-Instance-ID: six3DL4bMKTc7kTEG
|     Content-Type: text/html; charset=utf-8
|     Vary: Accept-Encoding
|     Date: Wed, 03 Nov 2021 17:12:34 GMT
|     Connection: close
|     <!DOCTYPE html>
|     <html>
|     <head>
|     <link rel="stylesheet" type="text/css" class="__meteor-css__" href="/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d.css?meteor_css_resource=true">
|     <meta charset="utf-8" />
|     <meta http-equiv="content-type" content="text/html; charset=utf-8" />
|     <meta http-equiv="expires" content="-1" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge" />
|     <meta name="fragment" content="!" />
|_    <meta name="distribution" content
10250/tcp open  ssl/http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=dev-01@1633275132
| Subject Alternative Name: DNS:dev-01
| Not valid before: 2021-10-03T14:32:12
|_Not valid after:  2022-10-03T14:32:12
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10255/tcp open  http        Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10257/tcp open  ssl/unknown
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Wed, 03 Nov 2021 17:12:42 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Wed, 03 Nov 2021 17:12:44 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1635957606
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2021-11-03T15:39:40
|_Not valid after:  2022-11-03T15:39:40
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10259/tcp open  ssl/unknown
| fingerprint-strings: 
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Wed, 03 Nov 2021 17:12:42 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     Date: Wed, 03 Nov 2021 17:12:44 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
| ssl-cert: Subject: commonName=localhost@1635957596
| Subject Alternative Name: DNS:localhost, DNS:localhost, IP Address:127.0.0.1
| Not valid before: 2021-11-03T15:39:40
|_Not valid after:  2022-11-03T15:39:40
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
16443/tcp open  ssl/unknown
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Wed, 03 Nov 2021 17:13:22 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   GenericLines, Help, Kerberos, RTSPRequest, SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Wed, 03 Nov 2021 17:12:42 GMT
|     Content-Length: 129
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
|   HTTPOptions: 
|     HTTP/1.0 401 Unauthorized
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     Date: Wed, 03 Nov 2021 17:12:44 GMT
|     Content-Length: 129
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"Unauthorized","reason":"Unauthorized","code":401}
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.114.171, IP Address:172.17.0.1
| Not valid before: 2021-11-03T16:27:50
|_Not valid after:  2022-11-03T16:27:50
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
25000/tcp open  ssl/http    Gunicorn 19.7.1
|_http-server-header: gunicorn/19.7.1
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=127.0.0.1/organizationName=Canonical/stateOrProvinceName=Canonical/countryName=GB
| Subject Alternative Name: DNS:kubernetes, DNS:kubernetes.default, DNS:kubernetes.default.svc, DNS:kubernetes.default.svc.cluster, DNS:kubernetes.default.svc.cluster.local, IP Address:127.0.0.1, IP Address:10.152.183.1, IP Address:10.10.114.171, IP Address:172.17.0.1
| Not valid before: 2021-11-03T16:27:50
|_Not valid after:  2022-11-03T16:27:50
31337/tcp open  http        nginx 1.21.3
|_http-server-header: nginx/1.21.3
|_http-title: Heroic Features - Start Bootstrap Template
32000/tcp open  http        Docker Registry (API: 2.0)
|_http-title: Site doesn't have a title.
4 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port3000-TCP:V=7.91%I=7%D=11/3%Time=6182C300%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,31C4,"HTTP/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-Co
SF:ntent-Type-Options:\x20nosniff\r\nX-Frame-Options:\x20sameorigin\r\nCon
SF:tent-Security-Policy:\x20default-src\x20'self'\x20;\x20connect-src\x20\
SF:*;\x20font-src\x20'self'\x20\x20data:;\x20frame-src\x20\*;\x20img-src\x
SF:20\*\x20data:;\x20media-src\x20\*\x20data:;\x20script-src\x20'self'\x20
SF:'unsafe-eval'\x20;\x20style-src\x20'self'\x20'unsafe-inline'\x20\r\nX-I
SF:nstance-ID:\x20six3DL4bMKTc7kTEG\r\nContent-Type:\x20text/html;\x20char
SF:set=utf-8\r\nVary:\x20Accept-Encoding\r\nDate:\x20Wed,\x2003\x20Nov\x20
SF:2021\x2017:12:32\x20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20htm
SF:l>\n<html>\n<head>\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/
SF:css\"\x20class=\"__meteor-css__\"\x20href=\"/a3e89fa2bdd3f98d52e474085b
SF:b1d61f99c0684d\.css\?meteor_css_resource=true\">\n<meta\x20charset=\"ut
SF:f-8\"\x20/>\n\t<meta\x20http-equiv=\"content-type\"\x20content=\"text/h
SF:tml;\x20charset=utf-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20con
SF:tent=\"-1\"\x20/>\n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content
SF:=\"IE=edge\"\x20/>\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>
SF:\n\t<meta\x20name=\"distribution\"\x20content")%r(HTTPOptions,2CCA,"HTT
SF:P/1\.1\x20200\x20OK\r\nX-XSS-Protection:\x201\r\nX-Content-Type-Options
SF::\x20nosniff\r\nX-Frame-Options:\x20sameorigin\r\nContent-Security-Poli
SF:cy:\x20default-src\x20'self'\x20;\x20connect-src\x20\*;\x20font-src\x20
SF:'self'\x20\x20data:;\x20frame-src\x20\*;\x20img-src\x20\*\x20data:;\x20
SF:media-src\x20\*\x20data:;\x20script-src\x20'self'\x20'unsafe-eval'\x20;
SF:\x20style-src\x20'self'\x20'unsafe-inline'\x20\r\nX-Instance-ID:\x20six
SF:3DL4bMKTc7kTEG\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nVary:
SF:\x20Accept-Encoding\r\nDate:\x20Wed,\x2003\x20Nov\x202021\x2017:12:34\x
SF:20GMT\r\nConnection:\x20close\r\n\r\n<!DOCTYPE\x20html>\n<html>\n<head>
SF:\n\x20\x20<link\x20rel=\"stylesheet\"\x20type=\"text/css\"\x20class=\"_
SF:_meteor-css__\"\x20href=\"/a3e89fa2bdd3f98d52e474085bb1d61f99c0684d\.cs
SF:s\?meteor_css_resource=true\">\n<meta\x20charset=\"utf-8\"\x20/>\n\t<me
SF:ta\x20http-equiv=\"content-type\"\x20content=\"text/html;\x20charset=ut
SF:f-8\"\x20/>\n\t<meta\x20http-equiv=\"expires\"\x20content=\"-1\"\x20/>\
SF:n\t<meta\x20http-equiv=\"X-UA-Compatible\"\x20content=\"IE=edge\"\x20/>
SF:\n\t<meta\x20name=\"fragment\"\x20content=\"!\"\x20/>\n\t<meta\x20name=
SF:\"distribution\"\x20content");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10257-TCP:V=7.91%T=SSL%I=7%D=11/3%Time=6182C309%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,170,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Wed,\x2003\x20Nov
SF:\x202021\x2017:12:42\x20GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20get\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},
SF:\"code\":403}\n")%r(HTTPOptions,174,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Wed,\x2003\x20Nov
SF:\x202021\x2017:12:44\x20GMT\r\nContent-Length:\x20189\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20options\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Termina
SF:lServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnecti
SF:on:\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port10259-TCP:V=7.91%T=SSL%I=7%D=11/3%Time=6182C309%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,170,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Wed,\x2003\x20Nov
SF:\x202021\x2017:12:42\x20GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20get\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},
SF:\"code\":403}\n")%r(HTTPOptions,174,"HTTP/1\.0\x20403\x20Forbidden\r\nC
SF:ache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20application/j
SF:son\r\nX-Content-Type-Options:\x20nosniff\r\nDate:\x20Wed,\x2003\x20Nov
SF:\x202021\x2017:12:44\x20GMT\r\nContent-Length:\x20189\r\n\r\n{\"kind\":
SF:\"Status\",\"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\"
SF:,\"message\":\"forbidden:\x20User\x20\\\"system:anonymous\\\"\x20cannot
SF:\x20options\x20path\x20\\\"/\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n")%r(RTSPRequest,67,"HTTP/1\.1\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20
SF:close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(SSLSessionReq,67,"HTTP/1
SF:\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset
SF:=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Termina
SF:lServerCookie,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(TLSSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r
SF:\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close
SF:\r\n\r\n400\x20Bad\x20Request")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\
SF:x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnecti
SF:on:\x20close\r\n\r\n400\x20Bad\x20Request");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port16443-TCP:V=7.91%T=SSL%I=7%D=11/3%Time=6182C309%P=x86_64-pc-linux-g
SF:nu%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Typ
SF:e:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x
SF:20Bad\x20Request")%r(GetRequest,11A,"HTTP/1\.0\x20401\x20Unauthorized\r
SF:\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20applicatio
SF:n/json\r\nDate:\x20Wed,\x2003\x20Nov\x202021\x2017:12:42\x20GMT\r\nCont
SF:ent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\",\"
SF:metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"rea
SF:son\":\"Unauthorized\",\"code\":401}\n")%r(HTTPOptions,11A,"HTTP/1\.0\x
SF:20401\x20Unauthorized\r\nCache-Control:\x20no-cache,\x20private\r\nCont
SF:ent-Type:\x20application/json\r\nDate:\x20Wed,\x2003\x20Nov\x202021\x20
SF:17:12:44\x20GMT\r\nContent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\
SF:"apiVersion\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\"
SF::\"Unauthorized\",\"reason\":\"Unauthorized\",\"code\":401}\n")%r(RTSPR
SF:equest,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/
SF:plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Re
SF:quest")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(SSLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\
SF:r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnection:\x20clos
SF:e\r\n\r\n400\x20Bad\x20Request")%r(TerminalServerCookie,67,"HTTP/1\.1\x
SF:20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-
SF:8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(TLSSessionRe
SF:q,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain
SF:;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request
SF:")%r(Kerberos,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x
SF:20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Ba
SF:d\x20Request")%r(FourOhFourRequest,11A,"HTTP/1\.0\x20401\x20Unauthorize
SF:d\r\nCache-Control:\x20no-cache,\x20private\r\nContent-Type:\x20applica
SF:tion/json\r\nDate:\x20Wed,\x2003\x20Nov\x202021\x2017:13:22\x20GMT\r\nC
SF:ontent-Length:\x20129\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\"
SF:,\"metadata\":{},\"status\":\"Failure\",\"message\":\"Unauthorized\",\"
SF:reason\":\"Unauthorized\",\"code\":401}\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 4 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   200.64 ms 10.13.0.1
2   ... 3
4   340.52 ms 10.10.114.171

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 164.95 seconds

```
### We can now answer the first question

## Enumerate Web-Server

![2](https://user-images.githubusercontent.com/74853138/140143836-6f1792b1-56d5-4167-9f52-bf781ee09e49.png)


### We can now answer the second question


## Enumerate what Fran leave on the site

![3](https://user-images.githubusercontent.com/74853138/140148722-4a2abe87-91b6-488e-8ea5-e3e7f3598e90.png)

### We noticed that what Frank leave on site is file let's download this file and check it

![4](https://user-images.githubusercontent.com/74853138/140151111-45e381f4-7044-406a-8233-55b2ebda1b33.png)

### The content is credenatilas the password is encoded in Url. after decode the password, we got credantiuser:password, we can logging with it via SSH.

![5](https://user-images.githubusercontent.com/74853138/140155646-81d6df8b-0b5b-43d2-8ed4-b1867374a282.png)

### And now we can get user.txt


## Privilige Escalation.

![6](https://user-images.githubusercontent.com/74853138/140157969-2449a77c-c196-4afc-bc04-c18044e23027.png)


![7](https://user-images.githubusercontent.com/74853138/140158890-f1b71c3f-182f-42f6-8fd4-abac6c10579a.png)

### Let's search how we can get privilege with microk8s

![8](https://user-images.githubusercontent.com/74853138/140161715-faf0f478-6fa0-412d-906f-9a72bb454cc5.png)

![9](https://user-images.githubusercontent.com/74853138/140161821-a0b6478f-77ad-4330-af3c-e616080aa8cc.png)

![10](https://user-images.githubusercontent.com/74853138/140161889-86c63a8e-62fe-467d-bdea-55ed747e14c5.png)

![11](https://user-images.githubusercontent.com/74853138/140162064-d48be476-23ae-4f29-851a-ca5e7ba656c1.png)

### So we have 3 things important 
1- create file pod.yaml

2- find the right image name

3- execute the two commands

## Find the image

### We need to execute this command

```
frank@dev-01:~$ microk8s kubectl get node -o yaml

```
### and here our images name

![12](https://user-images.githubusercontent.com/74853138/140162868-083ed5f3-d43f-47de-a37e-c9ed06a3e96e.png)
![13](https://user-images.githubusercontent.com/74853138/140162876-6fb273ea-7742-4aca-8921-6f1c1dc59f04.png)

### Here the name of image
```
localhost:32000/bsnginx@sha256:59dafb4b06387083e51e2589773263ae301fe4285cfa4eb85ec5a3e70323d6bd
```
in port 32000 that we found in Nmap Scan

### Now we will creat our pod.yaml file with this image

![14](https://user-images.githubusercontent.com/74853138/140163539-be474ca7-3bbc-4c4c-bce8-6c3245c133b8.png)


### Save and execute the two commands 

microk8s kubectl apply -f pod.yaml

![15](https://user-images.githubusercontent.com/74853138/140163547-d1a7e70a-1534-45ab-9d87-5f2ecd6e9530.png)


microk8s kubectl exec -it hostmount /bin/bash


![16](https://user-images.githubusercontent.com/74853138/140163552-67c34a91-7b9a-48a9-a41a-6eb28606d7ae.png)

## Voila ! we are root!!





># Thanks.!
