#!/bin/sh -e

set -e

if [ $# -ne 2 ]; then
	echo "specify top directory, and program names"
	exit 2
fi

TOP=$1
PRG=$2

cd $TOP
for component in *; do
	if [ -f "$component/tests/$PRG" ]; then
		echo "<<<<< Running tests in '$component' >>>>>" 
		$component/tests/$PRG
	fi
done

for component in daemon/*; do
	if [ -f "$component/tests/$PRG" ]; then
		echo "<<<<< Running tests in '$component' >>>>>" 
		$component/tests/$PRG
	fi
done

