
BUILT_SOURCES = \
	asn1-def-test.h

asn1-def-test.h: test.asn
	asn1Parser -o asn1-def-test.h test.asn 
	
UNIT_AUTO = \
	unit-test-crypto.c \
	unit-test-data-asn1.c \
	unit-test-data-der.c \
	unit-test-data-openssl.c \
	unit-test-file-tracker.c \
	$(BUILT_SOURCES)

UNIT_PROMPT = 

UNIT_LIBS =  \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/common/libgkr-module-common.la

EXTRA_DIST = \
	test.asn \
	test-data

include $(top_srcdir)/tests/gtest.make
