
# The following need to be declared before this file is included:
#   TESTING_FILES    A list of C files with tests
#   TESTING_LIBS     Libraries to link the tests to
#   TESTING_FLAGS    C flags for tests
#   TESTING_SOURCES  Other sources for tests

# ------------------------------------------------------------------------------

INCLUDES=			\
	-I$(top_srcdir) 	\
	-I$(top_builddir) 	\
	-I$(srcdir)/..		\
	-I$(srcdir)/../..	\
	$(GTK_CFLAGS)		\
	$(GLIB_CFLAGS) 		\
	$(P11_TESTS_CFLAGS) 	\
	$(TESTING_FLAGS)

LIBS = \
	$(GTK_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(P11_TESTS_LIBS)

noinst_PROGRAMS= \
	run-tests

PREPROCESSED = \
	$(TESTING_FILES:.c=.i)

.c.i:
	@echo "#include \"testing/testing.h\"" > test-suite.h
	$(AM_V_GEN)$(CC) -E $(CFLAGS) $(INCLUDES)  -o $@ $<

.i.o:
	$(AM_V_GEN)$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<

test-suite.c: $(PREPROCESSED) Makefile.am $(top_srcdir)/testing/testing-build.sh
	sh $(top_srcdir)/testing/testing-build.sh -b test-suite $(PREPROCESSED)

test-suite.h: test-suite.c

run_tests_SOURCES = \
	test-suite.c test-suite.h \
	$(TESTING_SOURCES) \
	$(PREPROCESSED)

run_tests_LDADD = \
	$(TESTING_LIBS) \
	$(DAEMON_LIBS)

run_tests_CFLAGS = \
	$(TESTING_FLAGS) \
	$(GCOV_CFLAGS)

run_tests_LDFLAGS = \
	$(GCOV_LDFLAGS)

BUILT_SOURCES = \
	test-suite.c \
	test-suite.h

CLEANFILES = \
	$(PREPROCESSED) \
	$(BUILT_SOURCES)

EXTRA_DIST = \
	$(TESTING_FILES)

# ------------------------------------------------------------------------------
# Run the tests

test: $(noinst_PROGRAMS)
	TEST_DATA=$(srcdir)/test-data  gtester --verbose -k -m=slow ./run-tests

check-am: $(noinst_PROGRAMS) test
