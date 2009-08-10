UNIT_AUTO = \
	unit-test-secret-compat.c \
	unit-test-secret-data.c \
	unit-test-secret-object.c \
	test-secret-module.c test-secret-module.h

UNIT_PROMPT = 

UNIT_LIBS =  \
	$(top_builddir)/pkcs11/secret-store/libgck-secret-store.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/tests/gtest.make
