#!/bin/sh

INSTPATH=/tank/users/bz/vps
IMGDIR=/tank/users/bz/vps_zambcom/vps_zabcom/PATCHES
MKIMG=${INSTPATH}/usr/bin/mkimg
MKIMG=mkimg

ipmitool -U ADMIN -P ADMIN -I lanplus -H rabbit3-ipmi "power" off
ipmitool -U ADMIN -P ADMIN -I lanplus -H rabbit4-ipmi "power" off

sleep 60

/usr/sbin/makefs -f 10000 -s 8589934592 -o version=2 -D ${IMGDIR}/rootfs.img ${INSTPATH}

ipmitool -U ADMIN -P ADMIN -I lanplus -H rabbit3-ipmi "power" on
ipmitool -U ADMIN -P ADMIN -I lanplus -H rabbit4-ipmi "power" on

${MKIMG} -s bsd -p freebsd-ufs:=${IMGDIR}/rootfs.img -o ${IMGDIR}/disk-vps.img

echo -n "Waiting for rabbit3 o boot again: "
while `ping -c 1 -q rabbit3 > /dev/null 2>&1`; do
	sleep 1
	echo -n "."
done
echo " (30 more seconds)"
sleep 30

echo -n "Copy over to rabbit3? [Y/n] "
while read c ; do

	case "${c}" in
	[Yy])	break ;;
	[Nn])	exit 0 ;;
	*)	echo -n "Sorry, you said?  Copy over to rabbit3? [Y/n] " ;;
	esac
done

ssh test@rabbit3 "su root -c 'mount -t ufs /dev/ada0 /mnt'"
scp -p disk-vps.img run-bhyve.sh test@rabbit3:/mnt/bz/

# end
