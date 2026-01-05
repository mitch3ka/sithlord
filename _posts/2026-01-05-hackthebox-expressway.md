---
title: "HackTheBox: Expressway"
author: mitcheka
categories: [HackTheBox]
tags: [Psk cracking, Ike/IPSec, privilege escalation]
render_with_liquid: false
media_subpath: /images/hackthebox-expressway/
image:
  path: express.webp
---
Focused on `IPSec/IKE` recon and `PSK` cracking which gave an ssh passphrase that we used to gain initial foothold.A hostname -based sudo bypass enabled us to escalate our privileges to root.

![card index](room-card.webp){: width="800" height="600" }

## Reconnaissance
The TCP scan revealed only one port was open 
```console
$ nmap -sV -sC -p- 10.10.11.87
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 8 (protocol 2.0)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Since there was nothing to go about I did a wider scan for `UDP` which revealed an attack surface we could exploit

```console
$ nmap -sU -sV -sC -T4 10.10.11.87
PORT      STATE         SERVICE        VERSION
68/udp    open|filtered dhcpc
69/udp    open          tftp           Netkit tftpd or atftpd
500/udp   open          isakmp?
1044/udp  open|filtered dcutility
1885/udp  open|filtered vrtstrapserver
4500/udp  open|filtered nat-t-ike
5001/udp  open|filtered commplex-link
18258/udp open|filtered unknown
18888/udp open|filtered apc-necmp
```

## IKE Enumeration
The `Internet Security Association and Key Management Protocol(ISKMP)` is used for `IPSec/IKE` VPN key exchange and it is running open on UDP port **500**   so we test for PSK weakness

![ike index](ike-scan.webp){: width="800" height="600" }

The IKE Main mode handshake output shows that the peer requires a **pre-shared key(PSK)** and uses **3DES+SHA1** which is weak by modern standards.
Vendor IDs were also present(XAUTH,Dead Peer Detection)
Trying aggressive mode to see if the service leaked identity or PSK material.

![aggressive index](aggressive-scan.webp){: width="800" height="600" }


## PSK Capture
The aggressive mode scan returned an identity and a hash
-**ID(Type=ID_USER_FQDN, Value=ike@expressway.htb)**
-A PSK hash was returned and we saved to **psk.txt**

### PSK Cracking
Next I captured a full aggressive handshake and exported the PSK hash
![pshash index](psk-capture.webp){: width="800" height="600" }

Running an offline dictionary attack against the captured hash gives us a password.

![crack index](psk-crack.webp){: width="800" height="600" }

## Initial foothold
Since the only other open tcp port was ssh I logged in and we get a session as `ike` and also capture our first flag.

![shell index](user-ike.webp){: width="800" height="600" }

## Post exploitation
Running sudo -l I notice a custome denial message instead of the usual
```console
$ ike@expressway:~$ sudo -l
[sudo] password for ike: 
Sorry, user ike may not run sudo on expressway.
```
Next up I check which sudo binary is running which shows `/usr/local/bin/sudo` instead of `/usr/bin/sudo` which suggests a custom SUID root binary is a likely privesc vector.Also had to check for other SUIDs just in case.

![suid index](priv-enum.webp){: width="800" height="600" }

Now going back to the memberships of the user we notice it had proxy-related group membership so i check the log files in `/var/www/log` and found an entry for an internal hostname.

```console
$ ike@expressway:~$ ls -l /var/log/squid
-rw-r--r-- 1 proxy proxy 4778 Jul 23 01:19 access.log.1
$ ike@expressway:~$ cat /var/log/squid/access.log.1
...
1753229688.902 0 192.168.68.50 TCP_DENIED/403 3807 GET http://offramp.expressway.htb - HIER_NONE/- text/html
...
```

This log shows a client attempted to access `offramp.expressway.htb` which is an internal only hostname not visible to external networks.

### Privilege escalation
Putting 2 and 2 together we find an escalation path.A custome SUID  `sudo` binary existed at `/usr/local/bin/sudo`.The denial message referenced the current host`(expressway)` which would mean the custom sudo enforced a hostname-based policy.
Invoking the local binary targeting `offramp.expressway.htb` ,the command triggers an alternate code path in the custom sudo and we get a root shell and our final flag of the box.

![root index](root.webp){: width="800" height="600" }

`Note:the sudo version 1.9.17 and this matches a documented hostname-bypass EDB-ID: 52354`

<style>
.center img {        
  display:block;
  margin-left:auto;
  margin-right:auto;
}
.wrap pre{
    white-space: pre-wrap;
}

</style>
