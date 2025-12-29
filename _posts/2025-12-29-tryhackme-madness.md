---
title: "TryHackMe: Madness"
author: mitcheka
categories: [TryHackMe]
tags: [Privilege Escalation, linux, steganography, File carving]
render_with_liquid: false
media_subpath: /images/tryhackme-madness/
image:
  path: madness.webp
---

This was a fun and easy room about getting through `steganography` to find ssh credentials and privilege escalation using a vulnerable binary `screen-4.5.0` to gain root.

![card index](room-card.webp){: width="300" height="300" }

## Initial Enumeration
### Nmap scan

```console
$ nmap -sC -sV -vv -Pn -T4 -p- 10.82.180.71
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 62 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 ac:f9:85:10:52:65:6e:17:f5:1c:34:e7:d8:64:67:b1 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDnNdHQKU4ZvpWn7Amdx7LPhuwUsHY8p1O8msRAEkaIGcDzlla2FxdlnCnS1h+A84lzn1oubZyb5vMrPM8T2IsxoSU2gcbbgfq/3giAL+hmuKm/nD43OKRflSHlcpIVgwQOVRdEfbQSOVpV5VBtJziA1Xu2dts2WWtawDS93CBtlfyeh+BuxZvBPX2k8XPWwykyR6cWbdGz1AAx6oxNRvNShJ99c9Vs7FW6bogwLAe9SWsFi2oB7ti6M/OH1qxgy7ZPQFhItvI4Vz2zZFGVEltL1fkwk2dat8yfFNWwm6+/cMTJqbVb7MPt3jc9QpmJmpgwyWuy4FTNgFt9GKNOJU6N
|   256 dd:8e:5a:ec:b1:95:cd:dc:4d:01:b3:fe:5f:4e:12:c1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGMMalsXVdAFj+Iu4tESrnvI/5V64b4toSG7PK2N/XPqOe3q3z5OaDTK6TWo0ezdamfDPem/UO9WesVBxmJXDkE=
|   256 e9:ed:e3:eb:58:77:3b:00:5e:3a:f5:24:d8:58:34:8e (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB3zGVeEQDBVK50Tz0eNWzBJny6ddQfBb3wmmG3QtMAQ
80/tcp open  http    syn-ack ttl 62 Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD POST OPTIONS
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Based on the nmap scan there are two open ports;
- **Port 22** `SSH`
- **Port 80** `Apache httpd`

## Enumeration
Visiting the webserver we get an apache default page but something looks off at the top left.It looks like a broken image.

![apache index](landing-page.webp){: width="1200" height="600" }

Upon viewing the page source I find an image src.

![image index](landing-pagesc.webp){: width="1200" height="600" }

Using wget to download the image I do some analysing and since it is broken I perform a header check which reveals a discrepancy.

![header index](head-thm.webp){: width="1200" height="600" }

The image header for this is `PNG` instead of `JPG` as the file extension suggests.
I use `radare2` to change the header.

```console
$ r2 -q -w -c 'wx FF D8 FF E0 00 10 4A 46 49 46 00 01 @0; q' thm.jpg
$ radare2 -w thm.jpg                                                
[0x00000000]> px 16 @0
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x00000000  ffd8 ffe0 0010 4a46 4946 0001 0100 0001  ......JFIF......
[0x00000000]>
```
As you can see now the file is `JPEG File Interchange Format` and upon opening it again we get a hidden directory `/th1s_1s_h1dd3n`.

![hidden index](thm-conv.webp){: width="1200" height="600" }

Visiting the directory we get a webpage and for a while to be honest i'm abit stuck on what to do next because fuzzing for endpoints or parameters does not show anything.

![hidden-dir index](hidden-dir.webp){: width="1200" height="600" }

Viewing the source code I get a hint.

![hidden-dir index](hidden-dirsc.webp){: width="1200" height="600" }

I try appending the word secret as a parameter and 0 as a parameter value and I get an idea of what we're working with.Based on the earlier hint I script a python code to create a number list which I will use to `FUZZ` using `gobuster`.

```console
$ echo "for i in range(0,100): print(i)" > madness.py
$ python3 madness.py > secret.txt

$ gobuster fuzz -u http://10.82.180.71/th1s_1s_h1dd3n/?secret=FUZZ -w secret.txt
...
[Status=200] [Length=445] [Word=73] http://10.82.180.71/th1s_1s_h1dd3n/?secret=73
```
Using the parameter value I get more information ,a possible password but to what? I don't know yet.

![parameter index](hidden-par2.webp){: width="1200" height="600" }

After alot of thinking and brainstorming I decide to go back to the webserver image and use `steghide` to see if any data is hidden and yes it does.I use the password I acquired and it successfully works.A username is provided but looks encoded or rather mangled so I use `ROT13` to decipher it and we get a username `joker`.

![joker index](thm-jpg.webp){: width="1200" height="600" }

Now that we have a user what next?
Again I take some time to brainstorm again and the room description throws a subtle hint `Please note that this challenge does not require ssh brute forcing`.
And the next thing I notice is that there is an image in the room description so I try my luck since the username came from deciphering an image.
Lucky enough `steghide` shows it has embedded data which conveniently works just by hitting enter.

![madness index](madness-jpg.webp){: width="1200" height="600" }

> Sometimes the simplest,most elegant explanation is usually the one closer to the truth ~ Occam's razor.
{: .prompt-tip }

## Exploitation
Using the username we acquired and this new password we gain a shell as the user `joker` and also obtain our first flag of the challenge.

![shell index](shell.webp){: width="1200" height="600" }

## Post-exploitation
### Privilege Escalation
The next stage is privilege escalation and my first thought is too look for binary files with `SUID` bit and true enough we get one.After a little research I find an exploit from `exploit-db` with the `EDB-ID:41154`.I download the bash script to my attackbox using `searchsploit` and use wget to transfer the payload to the compromised target.

![searchsploit index](searchsploit.webp){: width="1200" height="600" }

![payload index](root-enum.webp){: width="1200" height="600" }

I make the script executable `chmod +x` and run it and voila we are root and also get our second and last flag of the challenge.


![root index](root-shell.webp){: width="1200" height="600" }

`Eeeeeeaaasssyyypeeeaaassyyy`



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
