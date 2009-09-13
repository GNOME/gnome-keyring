
asn1-def-test.h: test.asn
	$(ASN1PARSER) -o asn1-def-test.h $(srcdir)/test.asn

# Test files should be listed in order they need to run
UNIT_AUTO = \
	unit-test-attributes.c \
	unit-test-crypto.c \
	unit-test-data-asn1.c \
	unit-test-data-der.c \
	unit-test-object.c \
	unit-test-authenticator.c \
	unit-test-timer.c \
	unit-test-transaction.c \
	unit-test-store.c \
	unit-test-memory-store.c \
	unit-test-login.c \
	unit-test-data-file.c \
	unit-test-file-tracker.c \
	mock-locked-object.c mock-locked-object.h \
	test-module.c test-module.h \
	asn1-def-test.h

UNIT_PROMPT =

UNIT_LIBS =  \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/egg/libegg.la

EXTRA_DIST = \
	test.asn \
	test-data

include $(top_srcdir)/tests/gtest.make

# ---------------------------------------------------------------------

noinst_PROGRAMS += \
	dump-data-file

dump_data_file_SOURCES = \
	dump-data-file.c

dump_data_file_LDADD = \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/egg/libegg.la \
	$(DAEMON_LIBS)

