
UNIT_AUTO = \
	test-prompt-login.c

UNIT_PROMPT =

UNIT_LIBS = \
	$(top_builddir)/pkcs11/wrap-layer/libgkm-wrap-layer.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/ui/libgku-prompt.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/tests/gtest.make

EXTRA_DIST = \
	test-data