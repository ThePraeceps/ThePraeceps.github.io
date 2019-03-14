---
title: TryHackMe - HackBack 2019
layout: post
description: A write up of the TryHackMe HackBack 2019 University CTF
tags: ctf tryhackme
toc: true
---

# TryHackMe - HackBack 2019

## Task 1: Connect to our network 
Free points for connecting to the challenge network? Sweet. However, our University address range conflicted with the CTF address range things were a little harder. To get around this, I used a NAT adapter on my Kali VM to put it in a 192.0.0.0/8 address range, which solved the issue.
>
{% highlight bash %}
openvpn --config ./username.ovpn --daemon
{% endhighlight  %}

Once connected simply submit empty answers to get the points.

## Task 2: Pickle Rick [Web Exploitation] [Easy]

### Question 1: What is the first ingredient Rick needs?

As this is as an easy task I expected that either credentials or flags would be leaked somewhere on the page, opposed to through any fancy exploitation. If we look at the source code of the homepage we can see a username "hidden" as a comment.

>index.html
{:.filename}
{% highlight html %}
  <!--

    Note to self, remember username!

    Username: R1ckRul3s

  -->
{% endhighlight  %}

I next looked at the "robots.txt" file as that is a common place for information leakage. 
>robots.txt
{:.filename}
{% highlight text %}
Wubbalubbadubdub
{% endhighlight  %}

As this wasn't in the usual format of a robots.txt file, this looks like it could be a password or a flag. As it was an incorrect flag, I kept it for a potential password.

The next step was to locate a login form to use these credentials. Continuing with the obvious, "login.php" turned out to be the correct page for this.

After login, we are given a primitive web shell with limited command access. An "ls" command reveals a "Sup3rS3cretPickl3Ingred.txt" and "clue.txt" in the web directory. The first file gives us the answer to the first question.


>Sup3rS3cretPickl3Ingred.txt
{:.filename}
{% highlight text %}
mr. meeseek hair
{% endhighlight  %}

### Question 2: Whats the second ingredient Rick needs?

We got a clue from the web directory about the location of the second ingrediant.

>clue.txt
{:.filename}
{% highlight text %}
Look around the file system for the other ingrediant.
{% endhighlight  %}

My first thought was to go look at home directories, so I ran ls on /home/, which showed a "rick" user. Given this is a Rick and Morty themed task, that sounded promising. An "ls" of "/home/rick" shows us a "second ingredients" file. However, attempting to use the "cat" command gives you a "Command disabled" error. The workaround I thought of for this was to use grep to match everything and print it.
>
{% highlight bash %}
grep .* /home/rick/second\ ingredients
{% endhighlight  %}

<!-- -->
>/home/rick/second ingredients
{:.filename}
{% highlight text %}
1 jerry tear
{% endhighlight  %}

### Question 3: Whats the final ingredient Rick needs?

As this is the last flag, I assumed it would likely be in root. However, we don't have permissions to browse that directory yet. Originally I used Perl to create a reverse shell to use sudo as I thought a TTY would be required, however, it turns out we can just use sudo from this web terminal. A "sudo ls" of "/root" shows us a "3rd.txt" which looks like what we are looking for.
>{% highlight bash %}
sudo grep .* /root/3rd.txt
{% endhighlight  %}
<!-- -->
>/root/3rd.txt
{:.filename}
{% highlight text %}
fleeb juice
{% endhighlight  %}

## Task 3: Gotta Catch em All [Scripting] [Medium]

To complete this challenge we need to understand what it wants us to create. It tells us that we need to connect to a specified port, do an operation on a number, and move on to the next port.

It gives us the format of "operation, number, next port" for each connection. The start conditions are to start on port 1337 and the sum at 0. The finish conditions are port 9765 or if STOP is in the page response. After which, the result should be printed.

The operations given are "add" and "minus", however, during testing I also found "multiply" and "divide".

The question tells us to give the answer to 2 decimal places, meaning our sums should be implemented as a float rather than an integer.

The IP that this challenge is deployed on, also tells us what port is currently open on port 3010.

Due to the nature of networking, it is also important to implement catching exceptions when connections inevitably fail.

Given these conditions here is my code:

>getflag.py
{:.filename}
{% highlight python %}
import socket
from time import sleep
ip="DEPLOYED IP"
getpage="GET / HTTP/1.1\nHost:" + ip + "\n\n"
def getopenport():
	portstart="<a target=\"_blank\" id=\"onPort\""
	portend="</a"
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect((ip, 3010))
		s.send(getpage.encode())
		httpdata=s.recv(1024)
		httpdata+=s.recv(1024)
		page=httpdata.decode()
		s.close()
		return int(page[page.find(portstart)+len(portstart):page.find(portend)])
	except:
		return 0

def processline(line, current_total):
	data=line.split()
	total=0
	operation=data[0]
	value=float(data[1])
	nextport=int(data[2])
	if "add" in operation:
		total=current_total+value
	elif "minus" in operation:
		total=current_total-value
	elif "multiply" in operation:
		total=current_total*value
	elif "divide" in operation:
		total=current_total/value
	else:
		print("ERROR!!!")
		print(line)
	return nextport, total

lastport=0
currentport=0
desiredport=1337
total=float(0)

while(True):
	currentport=getopenport()
	if(currentport != lastport):
		if(currentport != 0):
			lastport=currentport
			print("Current Port: " + str(currentport))
	if(currentport==desiredport):
		sleep(0.5)
		try:
			s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			s.connect((ip, desiredport))
			s.send(getpage.encode())
			httpdata=s.recv(1024)
			httpdata+=s.recv(1024)
			page=httpdata.decode()
			s.close()
			if "STOP" in page:
				break
			lines=page.split("\n")
			print("Recieved: " + lines[-1])
			desiredport, total=processline(lines[-1], total)
			if desiredport == 9765:
				break
			print("Current Total: " + str(total))
		except:
			print("Connection failed to: " + ip + ":" + str(currentport))
	else:
		sleep(1)
print("Finished the final total is:")
print(round(total,2))
{% endhighlight  %}





