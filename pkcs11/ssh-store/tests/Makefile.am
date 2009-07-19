UNIT_AUTO = \
	unit-test-ssh-openssh.c \
	unit-test-private-key.c \
	test-ssh-module.c test-ssh-module.h

UNIT_PROMPT = 

UNIT_LIBS =  \
	$(top_builddir)/pkcs11/ssh-store/libgck-ssh-store.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/tests/gtest.make

p11-tests:
	p11-tests -f p11-tests.conf ../.libs/gck-ssh-store-standalone.so

EXTRA_DIST = \
	test-data
