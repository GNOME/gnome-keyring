
UNIT_AUTO = \
	test-module.c

UNIT_PROMPT =

UNIT_LIBS = \
	$(top_builddir)/pkcs11/user-store/libgck-user-store.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/tests/gtest.make

EXTRA_DIST = \
	test-data \
	p11-tests.conf
