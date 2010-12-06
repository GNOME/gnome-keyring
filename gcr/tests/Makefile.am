
# Test files should be listed in order they need to run
TESTING_FILES = \
	test-certificate.c \
	test-simple-certificate.c \
	test-pkcs11-certificate.c \
	test-trust.c \
	unit-test-parser.c

TESTING_LIBS =  \
	$(top_builddir)/gcr/libgcr@GCR_VERSION_SUFFIX@.la \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/egg/libegg-entry-buffer.la \
	$(top_builddir)/gck/libgck.la

TESTING_FLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE \
	-DGCK_API_SUBJECT_TO_CHANGE

include $(top_srcdir)/testing/testing.make

EXTRA_DIST = \
	test-data

# ------------------------------------------------------------------

noinst_PROGRAMS += \
	ui-test-certificate \
	ui-test-key \
	ui-test-unlock-options

ui_test_certificate_SOURCES = \
	ui-test-certificate.c

ui_test_certificate_CFLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE \
	$(GTK_CFLAGS)

ui_test_certificate_LDADD = \
	$(top_builddir)/gcr/libgcr@GCR_VERSION_SUFFIX@.la \
	$(top_builddir)/gck/libgck.la \
	$(GTK_LIBS) \
	$(LIBGCRYPT_LIBS)

ui_test_unlock_options_SOURCES = \
	ui-test-unlock-options.c

ui_test_unlock_options_CFLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE \
	$(GTK_CFLAGS)

ui_test_unlock_options_LDADD = \
	$(top_builddir)/gcr/libgcr@GCR_VERSION_SUFFIX@.la \
	$(top_builddir)/gck/libgck.la \
	$(GTK_LIBS) \
	$(LIBGCRYPT_LIBS)

ui_test_key_SOURCES = \
	ui-test-key.c

ui_test_key_CFLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE \
	$(GTK_CFLAGS)

ui_test_key_LDADD = \
	$(top_builddir)/gcr/libgcr@GCR_VERSION_SUFFIX@.la \
	$(top_builddir)/gck/libgck.la \
	$(GTK_LIBS) \
	$(LIBGCRYPT_LIBS)
