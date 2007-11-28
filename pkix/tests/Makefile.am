
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
	run-pkix-test 
	
# ------------------------------------------------------------------------------
# PKIX tests 

BUILT_SOURCES = \
	asn1-def-test.h
	
UNIT_TESTS_PKIX = \
	unit-test-gcrypt-setup.c \
	unit-test-memory-stubs.c \
	unit-test-pkix-asn1.c \
	unit-test-pkix-der.c \
	unit-test-pkix-parser.c

asn1-def-test.h: test.asn
	asn1Parser -o asn1-def-test.h test.asn 
	
run-pkix-test.c: $(UNIT_TESTS_PKIX) Makefile.am
	sh $(top_srcdir)/tests/unit-tests-prep.sh -b run-pkix-test $(UNIT_TESTS_PKIX)

run_pkix_test_SOURCES = \
	run-pkix-test.c \
	run-pkix-test.h \
	$(UNIT_TESTS_PKIX) \
	$(BUILT_SOURCES)
	
run_pkix_test_LDADD = \
	$(top_builddir)/pkix/libgkr-pkix.la \
	$(top_builddir)/common/libgkr-common.la \
	$(DAEMON_LIBS)


# ------------------------------------------------------------------------------
# Run the tests

run-auto-tests: $(noinst_PROGRAMS)
	./run-pkix-test

run: $(noinst_PROGRAMS) run-auto-tests

