
INCLUDES=				\
	-I$(top_srcdir) 		\
	-I$(top_builddir) 		\
	$(GTK_CFLAGS)			\
	$(GLIB_CFLAGS) 
	
LIBS = \
	$(GTK_LIBS) \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS)
	
noinst_PROGRAMS= \
	run-pk-test 
	
# ------------------------------------------------------------------------------
# PK tests 
	
UNIT_TESTS_PK = \
	unit-test-memory-stubs.c \
	unit-test-pk-index.c 

run-pk-test.c: $(UNIT_TESTS_PK) Makefile.am
	sh $(top_srcdir)/tests/unit-tests-prep.sh -b run-pk-test $(UNIT_TESTS_PK)

run_pk_test_SOURCES = \
	run-pk-test.c \
	run-pk-test.h \
	$(UNIT_TESTS_PK)
	
run_pk_test_LDADD = \
	$(top_builddir)/pk/libgkr-pk.la \
	$(top_builddir)/common/libgkr-common.la \
	$(DAEMON_LIBS)

# ------------------------------------------------------------------------------
# Run the tests

run-auto-tests: $(noinst_PROGRAMS)
	./run-pk-test

run: $(noinst_PROGRAMS) run-auto-tests
