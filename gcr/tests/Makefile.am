
# Test files should be listed in order they need to run
UNIT_AUTO = \
	unit-test-certificate.c \
	unit-test-parser.c

UNIT_LIBS =  \
	$(top_builddir)/gcr/libgcr.la \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/egg/libegg-secure-entry.la \
	$(top_builddir)/gp11/libgp11.la
	
UNIT_FLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE

include $(top_srcdir)/tests/gtest.make

# ------------------------------------------------------------------

noinst_PROGRAMS += \
	ui-test-details

ui_test_details_SOURCES = \
	ui-test-details.c

ui_test_details_CFLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE \
	$(GTK_CFLAGS)
	
ui_test_details_LDADD = \
	$(top_builddir)/gcr/libgcr.la \
	$(GTK_LIBS) \
	$(LIBGCRYPT_LIBS) \
	$(LIBTASN1_LIBS)
	
EXTRA_DIST = \
	test-data
