
# Test files should be listed in order they need to run
TESTING_FILES = \
	unit-test-certificate.c \
	unit-test-parser.c

TESTING_LIBS =  \
	$(top_builddir)/gcr/libgcr.la \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/egg/libegg-entry-buffer.la \
	$(top_builddir)/gp11/libgp11.la
	
TESTING_FLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE

include $(top_srcdir)/testing/testing.make

# ------------------------------------------------------------------

noinst_PROGRAMS += \
	ui-test-details

ui_test_details_SOURCES = \
	ui-test-details.c

ui_test_details_CFLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE \
	$(GTK_CFLAGS)
	
ui_test_details_LDADD = \
	$(top_builddir)/gcr/libgcr@GCR_VERSION_SUFFIX@.la \
	$(GTK_LIBS) \
	$(LIBGCRYPT_LIBS)

EXTRA_DIST = \
	test-data
