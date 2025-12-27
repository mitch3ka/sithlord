---
title: "TryHackMe: DX1:Liberty Island"
author: mitcheka
categories: [TryHackMe]
tags: [web, data encoding, arbitrary command execution, IDOR]
render_with_liquid: false
media_subpath: /images/tryhackme-DX1/
image:
  path: DX1.webp
---

The room involved exploiting an `IDOR` vulnerability that helped acquire directives to get credentials by doing some short `encoding`  and gain root via `command injection over custom protocol` by intercepting traffic using `netcat`.

![card index](DX1-card.png){: width="300" height="300" }

## Enumeration
### Nmap scan

![nmap index](nmap.webp){: width="1200" height="600" }

Based on the nmap scan there are three ports I find interesting 
- **Port 80** `Apache httpd`
- **Port 5901** `VNC`
- **Port 23023** `Golang net/http server`

Next I fuzz for any hidden endpoints.

![ffuf index](ffuf.webp){: width="1200" height="600" }

The `robots.txt` endpoint gives us another directory we can look into.

![robots index](robots.txt.webp){: width="1200" height="600" }

But before I visit that endpoint I decide to look into the apache webserver first which shows a landing page.

![web index](web_index.webp){: width="1200" height="600" }

I look around for anything useful but none so I go back to check the `datacubes` endpoint which redirects us to `/datacubes/0000/`.

![datacubes index](datacubes.webp){: width="1200" height="600" }

The next thing that comes to mind is to test if the webserver is vulnerable to `IDOR` and after a couple of tries the endpoint `/datacubes/0011/` returns some sort of chatbox.

![datacubes index2](datacubes2.webp){: width="1200" height="600" }

But the credentials in the chatbox are redacted to prevent exposure but then I decide to go deeper just incase so I make a simple python script to automate this trial and error process.

```console
import requests

target = "10.80.141.88"

for i in range(0, 10000):
    r = requests.get(f"http://{target}/datacubes/" + format(i, '04'))
    if r.status_code == 200:
        print(format(i, '04') + '\n' + r.text)
```
The output yields a guide to get `VNC` credentials for a certain user.

![python script index](datacubes_script.webp){: width="1200" height="600" }

## Initial Access

The guide says that the VNC login for Jacobson's account is **'smashthestate'** hmac'ed with JL's username from the badactors list as the key and MD5 as the algorithm.The first 8 characters are the password.
Based on the list below it seems likely `jlebedev` is the most fitting for the initials `'JL'` 

![badactors index](badactors_page.webp){: width="1200" height="600" }

Now I can go to CyberChef to follow the steps to get the password.

![cyberchef index](cyberchef.webp){: width="1200" height="600" }

Looking back at the badactors page at the bottom,it is stated that the site is maintained by AJacobson so we can infer that this is the `VNC` username.

I use `Remmina` as the `VNC client` to login.

![remmina index](vnc-connect.webp){: width="1200" height="600" }

We are now finally on the box.

![box index](terminal.webp){: width="1200" height="600" }


Although the theme looks like windows ,it is a linux machine as confirmed by our nmap scan and also the terminal emulator runs a bash shell.

![bash index](enum1.webp){: width="1200" height="600" }

Opening the `user.txt` file gives us our first flag.

![flag1 index](user.txt.webp){: width="1200" height="600" }

## Privilege Escalation

The desktop has a `badactors-list` binary.Running this binary pops a UI window that loads the badactors list and allows me to edit it.Another thing to note is the binary starts by saying it is connecting to `UNATCO:23023` which is the port for the Golang server from our nmap scan.

![localhost index](localhost.webp){: width="1200" height="600" }

![badactors index](badactors-exec.webp){: width="1200" height="600" }

The binary is written in `Go` so it will be hard to decompile or use strings.Instead if it is really making a HTTP request then we have an approach;use a simple netcat listener on the box then start the badactors-list binary with a proxy setting pointing at the listener.
After setting up a listener I run the badactors-list via `HTTP_PROXY=localhost:4444 ./badactors-list` 
After a moment I capture a full request,complete with a clearence code and a suggestion that the directive argument is straight command execution as it is running `cat /var/www/html/badactors.txt`

![root1 index](root1.webp){: width="1200" height="600" }
![root2 index](root2.webp){: width="1200" height="600" }

Taking a look at the `badactors.txt` file I notice it is owned by root! which means we can write to files as root.

![var index](var-www-html.webp){: width="1200" height="600" }

Setting the clearance code as a header ,`curl -H 'Clearance-Code: 7gFfT74scCgzMqW4EQbu' -d 'directive=whoami' 10.80.141.88:23023` the result comes back as root and I am able to get the final flag at `/root/root.txt`.

![root3 index](root3.webp){: width="1200" height="600" }

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
