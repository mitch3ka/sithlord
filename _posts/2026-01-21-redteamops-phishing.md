---
title: "Red Team Ops: Phishing Campaign Using Covenant"
author: mitcheka
categories: [Red Team Ops]
tags: [windows, active directory, command & control, phishing]
render_with_liquid: false
media_subpath: /images/redteamops-phishing/
image:
  path: Phishh.webp
---

Phishing remains one of the most common entry points for threat actors abusing this TTP documented under MITRE ATT&CK framework `T1566.001`.Targeted spear phishing campaigns mimic trusted internal communications to harvest sensitive credentials,gain initial access or pivot to other workstations.All by tricking victims into clicking on malicious links which also sheds light on the issue of `social engineering` and awareness as well.
In this blog we can explore various techniques and tools used to engineer spear phishing campaigns specifically using `Covenant` as our command and control framework.

## Lab Architecture
Using this [github repo](https://github.com/dievus/adgenerator) I was able to build a mini Active Directory lab and configure a `Domain Controller` ,two workstations and a mail server.

![architecture index](network-architecture.webp){: width="700" height="500" }

Just to be sure I did some ping tests to confirm everything was operational

![ping index](ping-test.webp){: width="700" height="500" }

I also tested the mail server functionality.The mail client used in this case was `Thunderbird`

![email test index](testemail1.webp){: width="700" height="500" }

![email test2 index](test-email2.webp){: width="700" height="500" }

## Methodology
Steming from a password spray to a public facing mail server compromising a user with the credentials `a.tarolli:Summer2021!`
Sending phishing emails to the sender's list of the user a.tarolli ,the user s.chisholm gets compromised gaining a foothold on the external network and subsequent pivoting to the internal network and domain controller.
For this specific lab the only stage of the cyber kill chain that is focused on was command & control.The main objective is to show how spear phishing campaigns are executed.
Three techniques will be covered with proof of concept

## Out-Word Email Phishing
### Hosting and Payload Generation
After starting our covenant framework,the first step is to create a listener and update ip and port details

![listener index](listener.webp){: width="700" height="500" }

Next step is to create a powershell launcher for deploying `Grunts`
> Use high port numbers to avoid permission issues when using covenant.
{: .prompt-tip }

![launcher index](launcher.webp){: width="700" height="500" }

Configure the launcher using the following options

![launcher 2 index](powershell-launcher.webp){: width="700" height="500" }

Under the host tab,modify the path name of the launcher and click host to generate the payload

![launcher 3 index](powershell-encoded.webp){: width="700" height="500" }

Now that we have our payload we need to create a phishing document using  [Out-Word](https://github.com/samratashok/nishang/blob/master/Client/Out-Word.ps1)
Download the script to a windows machine and bear in mind Office has to be installed in order for the script to generate a word document with the embedded payload.
With the script and the payload we generated from the launcher we execute to get our malicious doc file

![outword index](out-word.webp){: width="700" height="500" }

Transfer the doc file to your attackbox and host the malicious payload in the listeners tab

![host index](hosted-files.webp){: width="700" height="500" }

Create and upload the doc file to host it on our C2 server.
Now the only thing left is how are we delivering our payload to the victim.
We have to craft an email capable of swindling an unsuspecting victim

Using a sample from [phishing pretexts github](https://github.com/L4bF0x/PhishingPretexts/tree/master/Phishing%20Pretexts) I pick the `GDPRPolicy.html` format.

Crafting an email with an updated link to download the malicious document we are set for the next stage

![gdpr index](GDPR.webp){: width="700" height="500" }

### Grunt
After sending the email,the user `s.chisholm` opens the email and downloads the document
> we have credentials for the user s.chisolm thats why we can log in on workstation 1 again as the user.This exercise is a methodical presentation of phishing not a complete kill chain.
{: .prompt-warning }

![sch index](gdpr-sch-inbox.webp){: width="700" height="500" }

By opening the file and enabling editing we trigger the payload that will execute the payload automatically

![trigger index](macro-enable.webp){: width="700" height="500" }

This results in a grunt on covenant

![grunt index](grunt01.webp){: width="700" height="500" }

## ISO Email Phishing
### Mark Of The Web (MOTW)
This is a metadata attribute that is added to files that are downloaded from the internet by browsers.
Represented as a comment in the file's header it has info about source of the file and the website it was downloaded from.
This allows web browsers to treat files downloaded from the internet differently from files on the local computer.
If the file has the Mark Of The Web the browser may display warning messages or restrict actions such as running scripts to protect the user from potential threats.
**MOTW BYPASS**
A research from [link](https://outflank.nl/blog/2020/03/30/mark-of-the-web-from-a-red-teams-perspective/) disclosed that some container file formats such as vhx,iso,vhd do not propagate the MOTW flag onto inner files upon auto mount or extraction.

A well documented tool used to bypass this by packing payloads into ISO files is available [github repo](https://github.com/mgeeky/PackMyPayload)

### ISO Creation
We shall generate an executable using covenant by selecting the binary option under launchers tab

![binary index](binary-launcher.webp){: width="700" height="500" }

Generate and download the binary file

![binary2 index](binary-launcher2.webp){: width="700" height="500" }

I renamed the file to **MSInstaller.exe** and used packmypayload to pack the executable

![exe index](packmypayload.webp){: width="700" height="500" }

Now that we have our payload we can craft an email same as before and send to our victim who upon execution gives us a grunt

![grunt index](msinstaller.webp){: width="700" height="500" }

![grunt 2 index](grunt02.webp){: width="700" height="500" }

## LNK Email Phishing
This is a windows shortcut file `.lnk` that is a pointer to an original file.It has metadata that allows us to execute mshta,powershell,vbscript or files dropped by the lnk
We can create an lnk file running a powershell encoded command.
Right click on the desktop to create a shortcut file and point it to the powershell binary located on `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`

![lnk index](lnk-pwsh.webp){: width="700" height="500" }

After this we edit the metadata on the shortcut by going to properties

![lnk2 index](lnk-pwsh2.webp){: width="700" height="500" }

Now edit the target to include the powershell payload we produced earlier when creating the Out-Word payload under launchers

![lnk3 index](lnk-pwsh3.webp){: width="700" height="500" }

![lnk4 index](lnk-pwsh-snap.webp){: width="700" height="500" }

We also changed the icon to make it look convincing 

![icon index](lnk-icon.webp){: width="700" height="500" }

> The lnk can also be packed to bypass MOTW.
{: .prompt-tip }

Using a security update pretext I was able to craft a phishing email that we could use to trick the victim into executing it.

![secup index](lnk-email-phish.webp){: width="700" height="500" }

It goes without saying that the techniques employed would trigger most security defenses but the objective was to show the methodology of phishing campaigns.
Feel free to use a command & control framework of your choosing or different file formats.
Next challenge will be a more covert phishing campaign aimed at bypassing modern EDRs.





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
