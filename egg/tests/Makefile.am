include $(top_srcdir)/Makefile.decl

ASN_FILES = \
	test.asn

ASN_SRCS = $(ASN_FILES:.asn=.asn.h)

BUILT_SOURCES = \
	$(ASN_SRCS)

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(GLIB_CFLAGS)

LDADD =  \
	$(top_builddir)/egg/libegg.la \
	$(LIBGCRYPT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS)

TEST_PROGS = \
	test-asn1 \
	test-dn \
	test-cleanup \
	test-hex \
	test-hkdf \
	test-oid \
	test-secmem \
	test-padding \
	test-symkey \
	test-openssl \
	test-dh \
	test-spawn

test_asn1_SOURCES = \
	test-asn1.c \
	$(ASN_SRCS)

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

check-local: test

all-local: $(check_PROGRAMS)

EXTRA_DIST = \
	$(ASN_FILES) \
	files

DISTCLEANFILES = \
	$(ASN_SRCS)

# ------------------------------------------------------------------------------

noinst_PROGRAMS = \
	test-asn1x

test_asn1x_SOURCES = \
	test-asn1x.c

test_asn1x_LDADD = \
	$(top_builddir)/egg/libegg-asn1x.la \
	$(LIBTASN1_LIBS) \
	$(LDADD)
