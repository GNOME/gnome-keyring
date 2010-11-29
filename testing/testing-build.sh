#!/bin/sh -eu

set -eu

# --------------------------------------------------------------------
# FUNCTIONS

usage()
{
	echo "usage: testing-build.sh -b base-name files.c ..." >&2
	exit 2
}

# --------------------------------------------------------------------
# SOURCE FILE

file_to_name()
{
	echo -n $1 | sed -E \
		-e 's/^(unit-)?test-//' \
		-e 's/\.c//' \
		-e 's/\.i//' | tr -c '[a-z0-9_]' '_'
}

testing_lines()
{
	grep -h "testing__" $@ /dev/null || true
}

build_header()
{
	echo "/* This is auto-generated code. Edit at your own peril. */"
	echo "#include \"testing/testing.h\""
	echo
	echo "#ifndef TESTING_HEADER_INCLUDED"
	echo "#define TESTING_HEADER_INCLUDED"
	echo

	testing_lines $@ | sed -ne 's/\(.*\)/\1;/p'

	echo
	echo "#endif /* TESTING_HEADER_INCLUDED */"
	echo
}

build_source()
{
	echo '/* This is auto-generated code. Edit at your own peril. */'
	echo "#include \"testing/testing.h\""
	echo "#include \"$BASE.h\""
	echo
	echo "typedef void (*TestingFunc)(int *, const void *);"
	echo

	lines="$(testing_lines $@)"

	# Startup function
	echo "static void start_tests (void) {"
		echo $lines | sed -n \
			-e "s/.*\(testing__start__[0-9a-z_]\+\).*/	\1 ();/p"
	echo "}"
	echo

	# Shutdown function
	echo "static void stop_tests (void) {"
		echo $lines | sed -n \
			-e "s/.*\(testing__stop__[0-9a-z_]\+\).*/	\1 ();/p"
	echo "}"
	echo

	# Add all tests to the test case
	echo "static void initialize_tests (void) {"
	first=YES
	for file in $@; do
		if [ "$first" = "YES" ]; then
			echo "	TestingFunc setup = NULL;"
			echo "	TestingFunc teardown = NULL;"
			first=NO
		fi

		name=$(file_to_name $file)
		echo "	setup = teardown = NULL;"

		testing_lines $file | sed -n \
			-e "s/.*\(testing__setup__[0-9a-z_]\+\).*/setup = \1;/p" \
			-e "s/.*\(testing__teardown__[0-9a-z_]\+\).*/teardown = \1;/p" \
			-e "s/.*testing__test__\([0-9a-z_]\+\).*/g_test_add(\"\/$name\/\1\", int, NULL, setup, testing__test__\1, teardown);/p"
	done
	echo "}"
	echo

	# External function
	echo "static void run_externals (int *ret) {"
		echo $lines | sed -n \
			-e "s/.*\(testing__external__[0-9a-z_]\+\).*/	testing_external_run (\"\1\", \1, ret);/p"
	echo "}"
	echo

	echo "static int run(void) {"
	echo "	int ret;"
	echo "	initialize_tests ();"
	echo "	start_tests ();"
	echo "	ret = g_test_run ();"
	echo "	if (ret == 0)"
	echo "		run_externals (&ret);"
	echo "	stop_tests();"
	echo "	return ret;"
	echo "}"

	echo "#include \"testing/testing.c\""
}

# --------------------------------------------------------------------
# ARGUMENT PARSING

BASE=unit

while [ $# -gt 0 ]; do
	case "$1" in
	-b)
		BASE="$2"
		shift
		;;
	--)
		shift
		break
		;;
	-*)
		usage
		;;
	*)
		break
		;;
	esac
	shift
done

build_header $@ > $BASE.h
build_source $@ > $BASE.c
