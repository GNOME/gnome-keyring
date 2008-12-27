UNIT_AUTO = \
	unit-test-ssh-openssh.c 

UNIT_PROMPT = 

UNIT_LIBS =  \
	$(top_builddir)/pkcs11/ssh-keys/libgck-ssh-keys.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/common/libgkr-module-common.la

include $(top_srcdir)/tests/gtest.make

p11-tests:
	p11-tests -f p11-tests.conf ../.libs/gck-ssh-keys-module.so
	