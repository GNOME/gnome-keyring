
# Test files should be listed in order they need to run
TESTING_FILES = \
	test-certificate.c \
	test-certificate-chain.c \
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

EXTRA_DIST += \
	test-data

# ------------------------------------------------------------------

INCLUDES += \
	-DGCR_API_SUBJECT_TO_CHANGE \
	-DGCK_API_SUBJECT_TO_CHANGE \
	$(GTK_CFLAGS)

LIBS += \
	$(top_builddir)/gcr/libgcr@GCR_VERSION_SUFFIX@.la \
	$(top_builddir)/gck/libgck.la \
	$(GTK_LIBS) \
	$(LIBGCRYPT_LIBS)

noinst_PROGRAMS += \
	test-ui-selector \
	ui-test-certificate \
	ui-test-key \
	ui-test-unlock-options
