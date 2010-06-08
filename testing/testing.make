
# The following need to be declared before this file is included:
#   TESTING_FILES    A list of C files with tests
#   TESTING_LIBS     Libraries to link the tests to
#   TESTING_FLAGS    C flags for tests

# ------------------------------------------------------------------------------

INCLUDES=				\
	-I$(top_srcdir) 		\
	-I$(top_builddir) 		\
	-I$(srcdir)/..			\
	-I$(srcdir)/../..		\
	$(GTK_CFLAGS)			\
	$(GLIB_CFLAGS) \
	$(P11_TESTS_CFLAGS)

LIBS = \
	$(GTK_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(P11_TESTS_LIBS)

noinst_PROGRAMS= \
	run-tests

test-framework.h: $(TESTING_FILES) Makefile.am $(top_srcdir)/testing/testing-build.sh
	sh $(top_srcdir)/testing/testing-build.sh -b test-framework $(TESTING_FILES)

test-framework.c: test-framework.h

run_tests_SOURCES = \
	test-framework.c test-framework.h \
	$(TESTING_FILES)

run_tests_LDADD = \
	$(TESTING_LIBS) \
	$(DAEMON_LIBS)

run_tests_CFLAGS = \
	$(TESTING_FLAGS) \
	$(GCOV_CFLAGS)

run_tests_LDFLAGS = \
	$(GCOV_LDFLAGS)

BUILT_SOURCES = \
	test-framework.c \
	test-framework.h

# ------------------------------------------------------------------------------
# Run the tests

test: $(noinst_PROGRAMS)
	TEST_DATA=$(srcdir)/test-data  gtester --verbose -k -m=slow ./run-tests

check-am: $(noinst_PROGRAMS) test
