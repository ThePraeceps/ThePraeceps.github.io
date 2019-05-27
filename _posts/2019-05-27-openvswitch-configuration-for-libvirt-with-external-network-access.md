---
title: Open vSwitch Configuration for Libvirt with External Network Access on Ubuntu 18.04
layout: post
description: How to install and configure Open vSwitch to provide networking for virtual machines hosted with libvirt and QEMU
tags: networking virtualisation
toc: true
---

In my virtualisation enviroment I use Open vSwitch to configure network connections between virtual machines and the external network. I use this as I find it easier to manage, and offers much more features when compared to the standard linux bridge. This includes more advanced tunneling capabilities which allow a switch fabric to be distributed accross multiple physical machines.

This guide is designed for Ubuntu 18.04, but may work on other Debian or Ubuntu versions.

# Installation

On Ubuntu this can be installed with the following package:
> sudo apt install openvswitch-switch

For virtualisation I use libvirt and qemu. This can be installed with the following package:
> sudo apt install libvirt-bin libvirt-doc virt-manager

Open vSwitch can now be configured using the "ovs-vsctl" utility. For example, the current configuration of the vSwitches can be displayed with the following command:
> sudo ovs-vsctl show 

# Bridge Setup

A bridge is created with the following command:
> sudo ovs-vsctl add-br [bridge name]

For my setup I usually create a "hosting" bridge for VMs that need external network access, and a "vuln" bridge for VMs that have known vulnerabilities and as such should not be given external network access.

# Connecting Virtual Machines

A virtual machine cannot be connected to a vSwitch using the "virt-manager" GUI - it must be added directly through the libvirt XML definition. This can be done through the virsh utility. For example:
> sudo virsh edit [vm name]

The interface can be defined under the devices node in the libvirt XML. The XML for an Open vSwitch interface is:

>
{% highlight xml %}
<interface type='bridge'>
	<source bridge='hosting'/>
	<virtualport type='openvswitch'/>
	<target dev='win10'/>
	<model type='virtio'/>
</interface>
{% endhighlight %}

# External Network Access

If a virtual machine requires external network access, there are two ways to do this. The first is to give the bridge an interface directly, and the other is to route the traffic through the host using NAT.

## Pass Ethernet Interface

The advantage to this method is that the virtual machines will appear as independent devices on the network. This means that they will get their own IP address and there is no need to configure the firewall on the host to allow access or forward ports to it.

There are two disadvantages to this method. The first is that this does not work through a WiFi interface, as the access point will not allow other MAC addresses to send traffic through it's connection. Due to this a WiFi interface can only be used in host mode to act as an access point for the bridge, not for accessing an external network. This must be done using the NAT method.

The second is that the host cannot use this interface at the same time as the bridge, or the bridge will be unable to send traffic through it. This can be solved by connecting the host through a different interface, or using the bridges "Internal" interface to connect the host to it. 


Before we add the interface to the bridge, we must unconfigure it on the host side. This can be done through the command line with:
> sudo ip addr flush dev [interface]

However, it is still possible that other parts of the operating system will reconfigure the interface perioidically. This is commonly due to Network Manager daemon, which will by default reconfigure the interface using DHCP. This can be disabled under the Setting GUI, and setting the configuration to manual.

The interface can now be added to the bridge with the following command:
> sudo ovs-vsctl add-port [interface]

Any other interface on the vSwitch should now be able to communicate to the external network. The host's bridge interface can be configured using the dhclient command as such:

> sudo dhclient -i [bridge name]

This configuration can be made consistent using the definitions found in the "/etc/network/interfaces" file. 

>/etc/network/interfaces
{:.filename}
{% highlight text %}
auto [interface]
iface [interface] inet manual
	pre-up ip link set dev [interface] up
	post-down ip link set dev [interface] down

auto [bridge name]
iface [bridge name] inet dhcp
	hwaddress ether de:ad:be:ef:00:01
	dns-nameservers 1.1.1.1,1.0.0.1
{% endhighlight %}

This configures the ethernet interface to come up on boot, but without an ip address. It also configures the bridge interface to use CloudFlare DNS servers and sets it's mac address on boot. This is important on the network this system is connected to uses a MAC whitelist to allow connections. Without this, the computer is unable to access the network. The MAC address can also be set in Open vSwitch with the following command:

> sudo ovs-vsctl set interface hosting mac=\"de:ad:be:ef:00:01\"

## NAT through Host

The advantage to this method is that the virtual machine will be complete invisible to the external network. This means that if network access is restricted, the virtual machine's traffic will appear to come from the device. In addition, the traffic from the device can be controlled using the hosts firewall rules, meaning that guest traffic can be restricted. This can be done to increase security if the guest is not fully trusted.

The disadvantages to this method is that if a device outside of the device needs to connect to the Virtual Machine, it will not be able to without forwarding the port in the hosts firewall rules. In addition it is harder overall to configure due to the need to configure firewall correctly to ensure traffic is managed correctly.

To do this, first ipv4 forwarding must be enabled for the system. This can be done by modifying the sysctl value in "/etc/sysctl.conf":

>/etc/sysctl.conf
{:.filename}
{% highlight text %}
net.ipv4.ip_forward = 1
{% endhighlight %}

The forwarding behaviour can then be configured with Uncomplicated Firewall (UFW) in Ubuntu 18.04.

The first step to doing this is to enable forwarding in the "/etc/default/ufw" configuration file. This is done by changing the "DEFAULT_FORWARD_POLICY" to ACCEPT.

>/etc/default/ufw
{:.filename}
{% highlight text %}
[lines before truncated]
DEFAULT_INPUT_POLICY="DROP"
DEFAULT_OUTPUT_POLICY="ACCEPT"
DEFAULT_FORWARD_POLICY="ACCEPT"
DEFAULT_APPLICATION_POLICY="SKIP"
[lines after truncated]
{% endhighlight %}

The second step to this is to add the forwarding rules to the "/etc/ufw/before.rules" rules file. This can be used to allow forwarding through an interface from an IP range, and to allow port forwarding. This should be added before the "\*filter" rules.

>/etc/ufw/before.rules
{:.filename}
{% highlight text %}
{% raw %}
*nat
:PREROUTING ACCEPT [0:0]
-A PREROUTING -i [wlan interface] -p tcp --dport [port to forward] -j DNAT --to-destination [ip address to forward to]

:POSTROUTING ACCEPT [0:0] 
-A POSTROUTING -s 192.168.1.0/24 -o [wlan interface] -j MASQUERADE

COMMIT

*filter
[lines after truncated]
{% endraw %}
{% endhighlight %}

The rules should then be reloaded with the following command:
> sudo ufw reload

The host's bridge interface can then be configured. As this interface does not directly have external network access, the interface must be configured manually. In my case I did this using the "/etc/network/interfaces" file. For this bridge I assigned it an address on the 192.168.1.0/24 subnet to match the firewall configuration above.

>/etc/network/interfaces
{:.filename}
{% highlight text %}
auto hosting
iface hosting inet static
	address 192.168.1.1
	netmask 255.255.255.0
{% endhighlight %}

Other hosts on the network will now be able to access the external network by using the host's IP address as a gateway. It should be noted that unless a DHCP server is setup on the host for the bridge interface, IP address for guests will need to be assigned manually.
