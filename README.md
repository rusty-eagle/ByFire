# ByFire
> This project provides a django web interface for a home or small business firewall.  

## ByFire firewall for Ubuntu
* [System Requirements](#system-requirements)
* [Installation](#installation)
* [Usage](#usage)
* [Todo](#todo)

## System Requirements
### Target firewall device
A default or minimal installation of Ubuntu 18.04.  For my use case, I am using an rk3328 ARM board, with a USB 3.0 gigabit ethernet adapter for the second network interface:

https://www.amazon.com/s?k=rk3328&ref=nb_sb_noss_2

### Computer to connect to target device
This could be the firewall device itself, but I use my laptop to connect to the firewall device.  On the device you use to run the installation against the firewall, you will need git and ansible.

## Installation
`git clone --depth 1 https://github.com/rusty-eagle/ByFire`
`cd ByFire`
`./install.sh`

Temporary steps:
* On the target device, you will want to login and run these commands to get the lists that are already expected to be there (for now):
`wget https://raw.githubusercontent.com/notracking/hosts-blocklists/master/dnsmasq/dnsmasq.blacklist.txt -O /etc/dnsmasq_blocklist.blacklist`
`wget https://raw.githubusercontent.com/notracking/hosts-blocklists/master/domains.txt -O /etc/dnsmasq_blocklist.domains`

Then use something like this to fix syntax errors in one of the lists:

`sed -i "s/\/#$/0\.0\.0\.0/g" /etc/dnsmasq_blocklist.*`

* Once logged into the web interface, you'll want to use the System > Interfaces tab, and edit the local area network config, and set the proper name.

## Usage
Once you have set this device upstream in your Internet connection, to access it, you just need to load this URL in a web browser:

http://fw.lan:8000

The default login is admin/byfire.  To change the password, currently you must update the /etc/nginx/htpasswd file.

`htpasswd /etc/nginx/htpasswd admin`

## Todo
* Automatically refresh blocklists (some lists have syntax errors, so they need to be parsed properly)
* Add the FastDrop XDP/BPF tool
* Add WireGuard support
* Solidify IPv6 Support
