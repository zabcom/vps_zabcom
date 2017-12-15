# $Id: Makefile 208 2013-12-17 15:33:25Z klaus $

.PATH:	${SRCTOP}/sys/vps

PROG=	vpsctl
SRCS+=	vpsctl.c
SRCS+=	priv_ston.c priv_ntos.c
SRCS+=	vps_libdump.c
MAN=	vpsctl.8 vps.4 vps.9 vps.conf.5
WARNS?=	6
LIBADD+=util

CLEANFILES+=	priv_ston.c priv_ntos.c

CFLAGS+= -I${SRCTOP}/sys

clean:
	rm -f vpsctl.o priv_ston.o priv_ntos.o vps_libdump.o \
		vpsctl mkprivlist \
		priv_ston.c priv_ntos.c \
		vpsctl.8.gz vps.4.gz vps.9.gz vps.conf.5.gz \
		vpsctl.8.html vps.conf.5.html vps.4.html vps.9.html mount_vpsfs.8.html \
		vpsctl.8.ps vps.conf.5.ps vps.4.ps vps.9.ps mount_vpsfs.8.ps \
		vpsctl.8.pdf vps.conf.5.pdf vps.4.pdf vps.9.pdf mount_vpsfs.8.pdf

#mkprivlist:
#	cc -Wall -g -o ./mkprivlist ${.CURDIR}/mkprivlist.c
#
#priv_ston.c priv_ntos.c: mkprivlist
#	./mkprivlist ${.CURDIR}/../../sys/sys/priv.h

mkprivlist:
	true

priv_generate:
	sh ${.CURDIR}/mkprivlist.sh ${.CURDIR}/../../sys/sys/priv.h

priv_ston.c priv_ntos.c: mkprivlist priv_generate

FOO_vpsctl: priv_ston.c priv_ntos.c
	cc -Wall -g -I../../sys -I/usr/include -o vpsctl \
		${.CURDIR}/vpsctl.c \
		./priv_ston.c \
		./priv_ntos.c \
		${.CURDIR}/../../sys/vps/vps_libdump.c

man2:
	groff -mdoc -Thtml vpsctl.8 > vpsctl.8.html
	groff -mdoc -Thtml vps.conf.5 > vps.conf.5.html
	groff -mdoc -Thtml vps.4 > vps.4.html
	groff -mdoc -Thtml vps.9 > vps.9.html
	groff -mdoc -Thtml ../../sbin/mount_vpsfs/mount_vpsfs.8 > mount_vpsfs.8.html
	groff -mdoc -Tps vpsctl.8 > vpsctl.8.ps
	groff -mdoc -Tps vps.conf.5 > vps.conf.5.ps
	groff -mdoc -Tps vps.4 > vps.4.ps
	groff -mdoc -Tps vps.9 > vps.9.ps
	groff -mdoc -Tps ../../sbin/mount_vpsfs/mount_vpsfs.8 > mount_vpsfs.8.ps
	ps2pdf vpsctl.8.ps vpsctl.8.pdf
	ps2pdf vps.conf.5.ps vps.conf.5.pdf
	ps2pdf vps.4.ps vps.4.pdf
	ps2pdf vps.9.ps vps.9.pdf
	ps2pdf mount_vpsfs.8.ps mount_vpsfs.8.pdf

.include <bsd.prog.mk>

# EOF
