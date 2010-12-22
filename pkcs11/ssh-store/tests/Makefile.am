TESTING_SOURCES = \
	test-ssh-module.h

TESTING_FILES = \
	unit-test-ssh-openssh.c \
	unit-test-private-key.c \
	test-ssh-module.c

UNIT_PROMPT =

TESTING_LIBS =  \
	$(top_builddir)/pkcs11/ssh-store/libgkm-ssh-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/testing/testing.make

EXTRA_DIST += \
	test-data
