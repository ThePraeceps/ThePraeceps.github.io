---
title: wip
layout: post
description: 
tags: ctf
date: 
toc: true
---

# Steganography

### Flag 1
Exif tool on Lenna

### Flag 2
Foremost to extract zip from Lenna
password was first flag's hex value
flag2.mp3 is a computer saying flag 2 is steganographyrules with no spaces

### Flag 3

Ran strings on "Stéphane.png" ( the longer one), flag is appended to the end of the file

### Flag 4
flag4 is a binary
ran strings on it
Saw "Nothing to see here.." followed by a base64 string
Got "stegosaurus" as the flag when decoded

### Flag 5

https://29a.ch/photo-forensics/#noise-analysis
Showed ascii characters in noise
Decoded to flag in hex
Also very visable in blue lsb

### Flag 6
Spent loads of time on this
"Intepreted outside the box" to being in the original file not the zip.
Saw some barcode like structure on the edge of the photo
Spent ages trying to decode it

Found original to have same barcode structure

On a whim downloaded the image next to the download button because that's outside of the box too
Ran exif tool 
flag 6


## Protecting Data In Transit

Vm is named heartbleed
Lots of heartbleed references
msf
scanner/ssl/openssl_heartbleed
Run till something that looks like a flag, guessed THM{} from previous challenges

## Investigating Windows
### Question 1
net localgroup Administrators
### Question 2
Look at task schduler
"Clean file system runs malicious netcat"

### Question 3
Task was created on 3/2/2019 - meaning it was compromised then

### Question 4
Windows Firewalls with Advanced Security
Inbound roles
Port 1337, "Aloow outside connections for developmnet"
Sounds fishy to me, correct answer
Correct way: Applications and services, Microsoft, Windows, Windows Firewall with Advanced Security
Gives same rule name


Event log: 
### Question 5
hosts file was in recent files
Show www.google resolving to a weird address as well as local host for virus services


### Question 6
Compromise begins at 3/2/2019 4:39:09 - powershell netcat is ran can see in powershell event log 
Event ID 4672



