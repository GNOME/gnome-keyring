#!/bin/sh -e

set -e

# --------------------------------------------------------------------
# FUNCTIONS 

usage()
{
	echo "usage: unit-test-prep.sh -b base-name files.c ..." >&2
	exit 2
}

# --------------------------------------------------------------------
# ARGUMENT PARSING

BASE=unit-test

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
	
FILES=$*

# --------------------------------------------------------------------
# HEADER FILE 

(

# HEADER TOP 
cat << END
/* This is auto-generated code. Edit at your own peril. */
#include "tests/cu-test/CuTest.h"
#include "tests/test-helpers.h"
#include <stdio.h>
#include <gtk/gtk.h>

END

# DECLARATIONS 

	if [ -n "$FILES" ]; then
		cat $FILES | grep '^void unit_setup_' | sed -e 's/$/;/'
		cat $FILES | grep '^void unit_test_' | sed -e 's/$/;/'
		cat $FILES | grep '^void unit_teardown_' | sed -e 's/$/;/'
	fi

) > $BASE.h

# --------------------------------------------------------------------
# SOURCE FILE 

(
# START RUNNER FUNCTION 
cat << END
/* This is auto-generated code. Edit at your own peril. */
#include "$BASE.h"

static void RunAllTests(void) 
{
    CuString *output = CuStringNew();
    CuSuite* suite = CuSuiteNew();

END

	if [ -n "$FILES" ]; then
		cat $FILES | grep '^void unit_setup_' | \
			sed -e 's/^void //' -e 's/(.*$//' -e 's/$/();/'
		cat $FILES | grep '^void unit_test_' | \
			sed -e 's/^void //' -e 's/(.*$//' \
        	             -e 's/^/SUITE_ADD_TEST(suite, /' -e 's/$/);/'
	fi

# MIDDLE RUNNER FUNCTION 
cat << END
    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\\n", output->buffer);
END

	if [ -n "$FILES" ]; then

		cat $FILES | grep '^void unit_teardown_' | \
			sed -e 's/^void //' -e 's/(.*$//' -e 's/$/();/'

	fi

# END RUNNER FUNCTION 
cat << END
}

#include "tests/test-helpers.c"
#include "tests/cu-test/CuTest.c"
END
) > $BASE.c

