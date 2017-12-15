#!/bin/sh

# Load modules before setting sysctls.
kldload vps_ddb 
kldload vps_dev 
kldload if_vps 
kldload vpsfs 
kldload vps_account 
kldload vps_suspend 
kldload vps_libdump 
kldload vps_snapst 
kldload vps_restore

sysctl -w net.inet.ip.forwarding=1 
sysctl -w net.inet6.ip6.forwarding=1
sysctl -w debug.vps_snapst_debug=0
sysctl -w debug.vps_restore_debug=0
sysctl -w debug.vps_core_debug=0
sysctl -w debug.vps_user_debug=0
sysctl -w debug.vps_if_debug=0
sysctl -w debug.vps_account_debug=0

ifconfig vps0 create 
ifconfig vps0 up

mount -t devfs devfs /vpsroot/dev

vpsctl start testvps
sleep 1
vpsctl suspend testvps
vpsctl list
vpsctl show testvps

# end
