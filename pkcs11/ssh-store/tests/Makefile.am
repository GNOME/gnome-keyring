UNIT_AUTO = \
	unit-test-ssh-openssh.c \
	unit-test-private-key.c \
	test-ssh-module.c test-ssh-module.h

UNIT_PROMPT =

UNIT_LIBS =  \
	$(top_builddir)/pkcs11/ssh-store/libgkm-ssh-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/tests/gtest.make

EXTRA_DIST = \
	test-data
