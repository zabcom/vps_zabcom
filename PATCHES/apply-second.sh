#!/bin/sh

#set -e
#set -x

case `uname -s` in
Darwin)		C_OPT="--dry-run" ;;
FreeBSD)	C_OPT="-C" ;;
*)		printf "ERROR: unsupported OS\n" >&2
		exit 1
		;;
esac

cd ..
test -e UPDATING
mkdir -p PATCHES/applied2

for f in `ls -1 PATCHES/applied/x*`; do

	printf "==> ${f} .. "
	patch ${C_OPT} -s -p1 -E -f < ${f}
	rc=$?
	case "${rc}" in
	0)
		printf "applying.\n"
		patch -s -p1 -E < ${f}
		rc2=$?
		case ${rc2} in
		0)	git mv ${f} PATCHES/applied2/
			printf "\n"
			;;
		*)	printf " FAILED.\n"
			;;
		esac
		;;
	*)
		printf "FAILED.\n"
		# Keep where they are.
		;;
	esac

done

# end
