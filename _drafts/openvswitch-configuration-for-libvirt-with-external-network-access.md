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
{% highlight xml % }
<interface type='bridge'>
	<source bridge='hosting'/>
	<virtualport type='openvswitch'/>
	<target dev='win10'/>
	<model type='virtio'/>
</interface>
{% endhighlight  %}

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

- add it to bridge

This configuration can be made consistent using the definitions found in the "/etc/network/interfaces" file. 
TODO: /etc/network/interfaces configuration from Heimdallr here

- Explain general layout
- Explain mac line

## NAT through Host

# Sources