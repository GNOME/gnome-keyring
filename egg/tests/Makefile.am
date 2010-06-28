asn1-def-test.h: test.asn
	$(ASN1PARSER) -o asn1-def-test.h $(srcdir)/test.asn

asn1-def-tests.h: tests.asn
	$(ASN1PARSER) -o asn1-def-tests.h $(srcdir)/tests.asn

# Test files should be listed in order they need to run
TESTING_FILES = \
	test-asn1.c \
	unit-test-asn1.c \
	test-dn.c \
	unit-test-cleanup.c \
	unit-test-hex.c \
	unit-test-oid.c \
	test-padding.c \
	unit-test-secmem.c \
	unit-test-symkey.c \
	unit-test-openssl.c \
	unit-test-dh.c \
	unit-test-spawn.c \
	asn1-def-test.h \
	asn1-def-tests.h

UNIT_PROMPT = 

TESTING_LIBS =  \
	$(top_builddir)/egg/libegg.la

EXTRA_DIST = \
	test.asn \
	tests.asn \
	test-data

include $(top_srcdir)/testing/testing.make

BUILT_SOURCES += \
	asn1-def-test.h

# ------------------------------------------------------------------------------

noinst_PROGRAMS += \
	test-asn1x

test_asn1x_SOURCES = \
	test-asn1x.c

test_asn1x_LDADD = \
	$(top_builddir)/egg/libegg-asn1x.la \
	$(LIBTASN1_LIBS)
