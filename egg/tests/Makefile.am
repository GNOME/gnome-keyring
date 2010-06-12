asn1-def-test.h: test.asn
	$(ASN1PARSER) -o asn1-def-test.h $(srcdir)/test.asn 

# Test files should be listed in order they need to run
TESTING_FILES = \
	unit-test-asn1.c \
	unit-test-cleanup.c \
	unit-test-hex.c \
	unit-test-oid.c \
	test-padding.c \
	unit-test-secmem.c \
	unit-test-symkey.c \
	unit-test-openssl.c \
	unit-test-dh.c \
	unit-test-spawn.c \
	asn1-def-test.h

UNIT_PROMPT = 

TESTING_LIBS =  \
	$(top_builddir)/egg/libegg.la

EXTRA_DIST = \
	test.asn \
	test-data

include $(top_srcdir)/testing/testing.make

BUILT_SOURCES += \
	asn1-def-test.h
