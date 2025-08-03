#!/bin/bash

modprobe ip_conntrack
sysctl -q -w net.ipv4.tcp_synack_retries=1
sysctl -q -w net.ipv4.tcp_syncookies=1
sysctl -q -w net.ipv4.tcp_timestamps=1
sysctl -q -w net.netfilter.nf_conntrack_max=10000000
sysctl -q -w net.netfilter.nf_conntrack_tcp_loose=0
ulimit -n 999999
ulimit -u 999999
ulimit unlimited
iptables -A INPUT -p tcp -m tcp --tcp-option 8 -j REJECT
iptables -A INPUT -p tcp -m tcp --tcp-option 5 -j REJECT
iptables -A INPUT -p tcp -m tcp --tcp-option 4 -j RETURN
apt install ipset -y
ipset create blocked hash:ip timeout 180000
iptables -A INPUT -p tcp -m tcp -m set --match-set blocked src -j DROP
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 -j DROP
iptables -A INPUT -p icmp -m limit --limit 10/sec --limit-burst 20 -j ACCEPT