
INCLUDES = \
	-I$(top_srcdir)/egg \
	-I$(top_srcdir)/gcr \
	-DSRCDIR=$(srcdir) \
	-DGCR_API_SUBJECT_TO_CHANGE \
	-DGCK_API_SUBJECT_TO_CHANGE \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

LDADD = \
	$(top_builddir)/gcr/libgcr@GCR_VERSION_SUFFIX@.la \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/egg/libegg-entry-buffer.la \
	$(top_builddir)/gck/libgck.la \
	$(GTK_LIBS) \
	$(GLIB_LIBS) \
	$(LIBGCRYT_LIBS)

TEST_PROGS = \
	test-certificate \
	test-certificate-chain \
	test-pkcs11-certificate \
	test-simple-certificate \
	test-trust \
	test-parser

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS)
	SRCDIR='$(srcdir)' gtester -k --verbose ${TEST_PROGS}

check-local: test

if WITH_TESTS
all-local: $(check_PROGRAMS)
endif

EXTRA_DIST = \
	files

# ------------------------------------------------------------------

noinst_PROGRAMS = \
	frob-certificate \
	frob-parser \
	frob-key \
	frob-unlock-options
