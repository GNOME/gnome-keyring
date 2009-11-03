# Test files should be listed in order they need to run
UNIT_AUTO = \
	unit-test-util.c

UNIT_PROMPT =

UNIT_LIBS =  \
	$(top_builddir)/daemon/prompt/libgkd-prompt.la \
	$(top_builddir)/egg/libegg-prompt.la

EXTRA_DIST = \
	test-data

include $(top_srcdir)/tests/gtest.make
