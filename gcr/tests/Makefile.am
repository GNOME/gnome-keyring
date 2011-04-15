
INCLUDES = \
	-I$(top_srcdir)/egg \
	-I$(top_srcdir)/gcr \
	-DSRCDIR=$(srcdir) \
	-DGCR_API_SUBJECT_TO_CHANGE \
	-DGCK_API_SUBJECT_TO_CHANGE \
	-DGCR_COMPILATION \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS) \
	$(LIBGCRYPT_CFLAGS)

LDADD = \
	$(top_builddir)/gcr/libgcr-testable.la \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/egg/libegg-entry-buffer.la \
	$(top_builddir)/gck/libgck.la \
	$(GTK_LIBS) \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

TEST_PROGS = \
	test-util \
	test-simple-certificate \
	test-certificate \
	test-certificate-chain \
	test-pkcs11-certificate \
	test-trust \
	test-parser \
	test-colons \
	test-gnupg-key \
	test-gnupg-collection

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS)
	SRCDIR='$(srcdir)' gtester -k --verbose ${TEST_PROGS}

check-local: test

if WITH_TESTS
all-local: $(check_PROGRAMS)
endif

EXTRA_DIST = \
	test-data

# ------------------------------------------------------------------

noinst_PROGRAMS = \
	frob-certificate \
	frob-gnupg-selector \
	frob-key \
	frob-selector \
	frob-unlock-options
