
asn1-def-test.h: test.asn
	$(ASN1PARSER) -o asn1-def-test.h $(srcdir)/test.asn

TESTING_SOURCES = \
	asn1-def-test.h \
	test-module.c test-module.h \
	mock-locked-object.c mock-locked-object.h

# Test files should be listed in order they need to run
TESTING_FILES = \
	unit-test-attributes.c \
	unit-test-sexp.c \
	unit-test-data-asn1.c \
	unit-test-data-der.c \
	unit-test-object.c \
	unit-test-credential.c \
	unit-test-timer.c \
	unit-test-transaction.c \
	unit-test-store.c \
	unit-test-memory-store.c \
	unit-test-secret.c \
	unit-test-file-tracker.c

TESTING_LIBS =  \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/testing/testing.make

EXTRA_DIST += \
	test.asn \
	test-data
