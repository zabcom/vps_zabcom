#!/bin/sh

#set -e
set -x

case `uname -s` in
Darwin)		C_OPT="--dry-run" ;;
FreeBSD)	C_OPT="-C" ;;
*)		printf "ERROR: unsupported OS\n" >&2
		exit 1
		;;
esac

cd ..
test -e UPDATING
for f in `ls -1 PATCHES/orig/x*`; do

	patch ${C_OPT} -s -p1 -B -f < ${f}
	rc=$?
	case "${rc}" in
	0)
		patch -s -p1 -B -f < ${f}
		mv -i ${f} PATCHES/applied/
		;;
	*)
		mv -i ${f} PATCHES/failed/
		;;
	esac

done

# end
