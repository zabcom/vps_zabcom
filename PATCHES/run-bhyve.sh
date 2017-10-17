#!/bin/sh

set -x -e

kldload vmm.ko || true

ifconfig tap0 create || true
ifconfig tap1 create || true
sysctl net.link.tap.up_on_open=1 || true

ifconfig bridge0 create || true
ifconfig bridge0 addm tap0 addm tap1 || true
ifconfig bridge0 up

cd /mnt/bz

cp -pf disk-vps.img disk-vm0.img
cp -pf disk-vps.img disk-vm1.img

test -e /dev/vmm/vm0 || \
	/usr/sbin/bhyveload -m 1G \
	-e autoboot_delay=1 \
	-e vfs.root.mountfrom="ufs:/dev/ada0a" \
	-e hint.uart.1.flags="0x80" \
	-e hostname="left" \
	-d ./disk-vm0.img vm0

test -e /dev/vmm/vm1 || \
	/usr/sbin/bhyveload -m 1G \
	-e autoboot_delay=1 \
	-e vfs.root.mountfrom="ufs:/dev/ada0a" \
	-e hint.uart.1.flags="0x80" \
	-e hostname="right" \
	-d ./disk-vm1.img vm1

/usr/sbin/bhyve -c 1 -m 1G -A -H -P \
	-s 0:0,hostbridge \
	-s 1:0,virtio-net,tap0 \
	-s 2:0,ahci-hd,./disk-vm0.img \
	-s 31,lpc \
	-l com1,/dev/nmdm0A \
	-l com2,/dev/nmdm1A \
	vm0 &

/usr/sbin/bhyve -c 1 -m 1G -A -H -P \
	-s 0:0,hostbridge \
	-s 1:0,virtio-net,tap1 \
	-s 2:0,ahci-hd,./disk-vm1.img \
	-s 31,lpc \
	-l com1,/dev/nmdm10A \
	-l com2,/dev/nmdm11A \
	vm1 &

echo "kgdb /usr/lib/debug/boot/kernel/kernel.debug"
echo "target remote /dev/nmdm1B"
echo "/usr/sbin/bhyvectl --destroy --vm=vm0"
echo "/usr/sbin/bhyvectl --destroy --vm=vm1"

# end
