
BUILT_SOURCES = \
	asn1-def-test.h

asn1-def-test.h: test.asn
	asn1Parser -o asn1-def-test.h test.asn 
	
UNIT_AUTO = \
	unit-test-gcrypt-setup.c \
	unit-test-pkix-asn1.c \
	unit-test-pkix-der.c \
	unit-test-pkix-openssl.c \
	unit-test-pkix-parser.c \
	unit-test-pkix-serialize.c \
	$(BUILT_SOURCES)

UNIT_PROMPT = 

UNIT_LIBS =  \
	$(top_builddir)/daemon/pkix/libgkr-pkix.la \
	$(top_builddir)/common/libgkr-common.la

EXTRA_DIST = \
	test.asn \
	test-data

include $(top_srcdir)/tests/test.make

