
# Test files should be listed in order they need to run
UNIT_AUTO = \
	unit-test-parser.c

UNIT_PROMPT = 

UNIT_LIBS =  \
	$(top_builddir)/gcr/libgcr.la \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/egg/libegg-secure-entry.la \
	$(top_builddir)/gp11/libgp11.la
	
UNIT_FLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE

include $(top_srcdir)/tests/gtest.make
