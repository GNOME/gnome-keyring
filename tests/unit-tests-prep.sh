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
	
# Must specify some files
if [ $# -eq 0 ]; then
	usage
fi

FILES=$*

# --------------------------------------------------------------------
# HEADER FILE 

(

# HEADER TOP 
cat << END
/* This is auto-generated code. Edit at your own peril. */
#include "cu-test/CuTest.h"
#include <stdio.h>
#include <gtk/gtk.h>

END

# DECLARATIONS 

	cat $FILES | grep '^void unit_setup_' | sed -e 's/$/;/'
	cat $FILES | grep '^void unit_test_' | sed -e 's/$/;/'
	cat $FILES | grep '^void unit_teardown_' | sed -e 's/$/;/'

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

	cat $FILES | grep '^void unit_setup_' | \
		sed -e 's/^void //' -e 's/(.*$//' -e 's/$/();/'
	cat $FILES | grep '^void unit_test_' | \
		sed -e 's/^void //' -e 's/(.*$//' \
                     -e 's/^/SUITE_ADD_TEST(suite, /' -e 's/$/);/'

# MIDDLE RUNNER FUNCTION 
cat << END
    CuSuiteRun(suite);
    CuSuiteSummary(suite, output);
    CuSuiteDetails(suite, output);
    printf("%s\\n", output->buffer);
END

	cat $FILES | grep '^void unit_teardown_' | \
		sed -e 's/^void //' -e 's/(.*$//' -e 's/$/();/'

# END RUNNER FUNCTION 
cat << END
}

#include "test-helpers.c"
#include "cu-test/CuTest.c"
END
) > $BASE.c

