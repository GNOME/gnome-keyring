include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/pkcs11 \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(GLIB_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

LDADD = \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBGCRYPT_LIBS)

noinst_LIBRARIES = libgkm-mock.a

libgkm_mock_a_SOURCES = \
	mock-module.c mock-module.h \
	mock-locked-object.c mock-locked-object.h \
	test.asn.h

TEST_PROGS = \
	test-attributes \
	test-credential \
	test-data-asn1 \
	test-data-der \
	test-file-tracker \
	test-memory-store \
	test-object \
	test-certificate \
	test-secret \
	test-sexp \
	test-store \
	test-timer \
	test-transaction

test_credential_LDADD = \
	libgkm-mock.a \
	$(LDADD)

test_memory_store_LDADD = \
	libgkm-mock.a \
	$(LDADD)

test_object_LDADD = \
	libgkm-mock.a \
	$(LDADD)

test_certificate_LDADD = \
	libgkm-mock.a \
	$(LDADD)

test_store_LDADD = \
	libgkm-mock.a \
	$(LDADD)

test_timer_LDADD = \
	libgkm-mock.a \
	$(LDADD)

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

check-local: test

all-local: $(check_PROGRAMS)

EXTRA_DIST = \
	test.asn \
	files

asn:
	asn1Parser -o test.asn.h test.asn
	sed -i 's|#include.*|/* \0 */|' test.asn.h
