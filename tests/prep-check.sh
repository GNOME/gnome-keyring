#!/bin/sh -eu

set -eu

# --------------------------------------------------------------------
# FUNCTIONS 

usage()
{
	echo "usage: prep-check.sh -b base-name files.c ..." >&2
	exit 2
}

# --------------------------------------------------------------------
# SOURCE FILE 

build_header()
{
	local _file
	
	echo '/* This is auto-generated code. Edit at your own peril. */'
	# echo "#ifndef _${BASE}_H_"
	# echo "#define _${BASE}_H_"
	echo 
	echo '#include <check.h>'
	echo
	echo 'extern SRunner *srunner;'
	echo
	echo '#define DEFINE_SETUP(x) void setup_##x(void)'
	echo '#define DEFINE_TEARDOWN(x) void teardown_##x(void)'
	echo '#define DEFINE_TEST(x) void x(void)'
	echo '#define DEFINE_ABORT(x) void x(void)'
	echo
	for _file in $@; do
		sed -ne 's/.*DEFINE_SETUP(\([^)]\+\))/	void setup_\1(void);/p' $_file
		sed -ne 's/.*DEFINE_TEARDOWN(\([^)]\+\))/	void teardown_\1(void);/p' $_file
		sed -ne 's/.*DEFINE_TEST(\([^)]\+\))/	void \1(void);/p' $_file
		sed -ne 's/.*DEFINE_ABORT(\([^)]\+\))/	void \1(void);/p' $_file
	done
	echo
	# echo "#endif"
}

build_source()
{
	local _tcases _file _name
	
	echo '/* This is auto-generated code. Edit at your own peril. */'
	echo '#include <check.h>'
	echo "#include \"tests/check-helpers.h\""
	echo "#include \"$BASE.h\""
	echo
	
	# A  test macro
	echo '#define WRAP_TEST(name) \'
	echo '	START_TEST(test_##name) { \'
	echo '		name (); \'
	echo '	} END_TEST'
	
	# Note that we can't run abort tests without CK_FORK
	echo '#define WRAP_ABORT(name) \'
	echo '	START_TEST(test_##name) { \'
	echo '		if (srunner_fork_status (srunner) == CK_NOFORK) return; \'
	echo '		GLogFunc old = g_log_set_default_handler (test_quiet_abort_log_handler, NULL); \'
	echo '		name (); \'
	echo '		g_log_set_default_handler (old, NULL); \'
	echo '	} END_TEST'
	
	# Include each file, and build a test case for it
	_tcases=""
	for _file in $@; do
		_name=`echo $_file | tr -c 'a-zA-Z0-9' '_'`  

		# Include the test file
		# echo "#include \"$_file\""
		# echo

		# Wrap each and every test
		sed -ne 's/.*DEFINE_TEST(\([^)]\+\)).*/WRAP_TEST (\1);/p' $_file
		sed -ne 's/.*DEFINE_ABORT(\([^)]\+\)).*/WRAP_ABORT (\1);/p' $_file
		echo
		
		# Add all tests to the test case 
		echo "static TCase* tcase_$_name(void) {"
		_tcases="$_tcases $_name"
		echo "	TCase *tc = tcase_create (\"X\");"
		sed -ne 's/.*DEFINE_SETUP(\([^)]\+\)).*/	tcase_add_checked_fixture (tc, setup_\1, teardown_\1);/p' $_file
		sed -ne 's/.*DEFINE_TEST(\([^)]\+\)).*/	tcase_add_test (tc, test_\1);/p' $_file
		sed -ne 's/.*DEFINE_ABORT(\([^)]\+\)).*/	tcase_add_test_raise_signal (tc, test_\1, 6);/p' $_file
		echo "	return tc;"
		echo "}"
		echo
		
	done
	
	echo "static Suite* test_suite_create (void) {"
	echo "	Suite *s = suite_create (\"$BASE\");"
	for _name in $_tcases; do
		echo "	suite_add_tcase (s, tcase_$_name());"
	done
	echo "	return s;"
	echo "}"
	echo
		
	echo "#include \"tests/check-helpers.c\""
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
	
build_header $* > $BASE.h
build_source $* > $BASE.c
