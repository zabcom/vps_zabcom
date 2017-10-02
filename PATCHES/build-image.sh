#!/bin/sh

INSTPATH=/tank/users/bz/vps
IMGDIR=/tank/users/bz/vps_zambcom/vps_zabcom/PATCHES
MKIMG=${INSTPATH}/usr/bin/mkimg
MKIMG=mkimg

/usr/sbin/makefs -f 10000 -s 8589934592 -D ${IMGDIR}/rootfs.img ${INSTPATH}
${MKIMG} -s bsd -p freebsd-ufs:=${IMGDIR}/rootfs.img -o ${IMGDIR}/disk-vps.img
cp -fp ${INSTPATH}/boot/kernel/kernel ${IMGDIR}/kernel.vps

echo -n "Copy over to rabbit3? [Y/n] "
while read c ; do

	case "${c}" in
	[Yy])	break ;;
	[Nn])	exit 0 ;;
	*)	echo -n "Sorry, you said?  Copy over to rabbit3? [Y/n] " ;;
	esac
done

scp -p kernel.vps disk-vps.img test@rabbit3:/mnt/bz/

# end
