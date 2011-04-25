
INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	-DSRCDIR="\"$(srcdir)\"" \
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
	$(top_builddir)/gck/libgck-testable.la \
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
	gtester -k --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

check-local: test

all-local: $(check_PROGRAMS)

EXTRA_DIST = \
	files

# ------------------------------------------------------------------

noinst_PROGRAMS = \
	frob-certificate \
	frob-gnupg-selector \
	frob-parser \
	frob-key \
	frob-selector \
	frob-unlock-options
