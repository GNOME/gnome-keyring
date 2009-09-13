asn1-def-test.h: test.asn
	$(ASN1PARSER) -o asn1-def-test.h $(srcdir)/test.asn 

# Test files should be listed in order they need to run
UNIT_AUTO = \
	unit-test-asn1.c \
	unit-test-cleanup.c \
	unit-test-hex.c \
	unit-test-oid.c \
	unit-test-secmem.c \
	unit-test-symkey.c \
	unit-test-openssl.c \
	asn1-def-test.h

UNIT_PROMPT = 

UNIT_LIBS =  \
	$(top_builddir)/egg/libegg.la

EXTRA_DIST = \
	test.asn \
	test-data

include $(top_srcdir)/tests/gtest.make

BUILT_SOURCES += \
	asn1-def-test.h
