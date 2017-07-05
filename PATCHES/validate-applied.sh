#!/bin/sh


for f in `find applied -type f`; do

	echo "==> ${f}"
	sf=`head -2 ${f} | awk '/^---/ { gsub("10.0.0-stripped/", "", $2); print $2; }'`
	ch=`git log ../${sf} | head -1 | awk '{ print $2 }'`
	case "${ch}" in
	3548d19e32d39641cf8a2f21537a8ad408ab1af5)
		git mv ${f} applied1/
		;;
	*)	printf "ERROR: ${f} ${sf} ${ch}\n"
		git log 210e89f9f540d85049124ce9fed8ff9b2ca1e1fc.. ../${sf}
		#exit 1
		;;
	esac

done

# commit 3548d19e32d39641cf8a2f21537a8ad408ab1af5

# end
