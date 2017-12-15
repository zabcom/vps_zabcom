#!/bin/sh

xPWD=`pwd`
bn=`basename ${xPWD}`
case ${bn} in
PATCHES)	;;
*)		echo "run from PATCHES directory" >&2
		exit 2
		;;
esac

INSTPATH=/tank/users/bz/vps_zambcom/inst
IMGDIR=/tank/users/bz/vps_zambcom/vps_zabcom/PATCHES
MKIMG=${INSTPATH}/usr/bin/mkimg
MKIMG=mkimg

mkdir -p ${INSTPATH}/vpsroot
(cd .. && make -s installworld distribution installkernel KERNCONF=VPS_DBG DESTDIR=${INSTPATH}/ )
(cd .. && make -s installworld distribution KERNCONF=VPS_DBG DESTDIR=${INSTPATH}/vpsroot )

mkdir -p ${INSTPATH}/etc/vps
cp -pf vps_testvps.conf ${INSTPATH}/etc/vps/
cp -pf vps-m.sh vps.sh vps2.sh init.sh ${INSTPATH}/root/
cp -pf init.sh ${INSTPATH}/vpsroot/root/

echo "/dev/ada0p2	/	ufs	rw	0 0" > ${INSTPATH}/etc/fstab

/usr/sbin/makefs -f 10000 -s 8589934592 -o version=2 -D ${IMGDIR}/rootfs.img ${INSTPATH}

${MKIMG} \
	-f qcow2 \
	-s gpt \
	-b ${INSTPATH}/boot/pmbr \
	-p freebsd-boot:=${INSTPATH}/boot/gptboot \
	-p freebsd-ufs:=${IMGDIR}/rootfs.img \
	-o ${IMGDIR}/disk-qemu.qcow2

ssh test@rabbit3 "su root -c 'mount -t ufs /dev/ada0 /mnt'"
scp -p disk-qemu.qcow2 run-qemu.sh test@rabbit3:/mnt/bz/

# end
