
UNIT_AUTO = \
	unit-test-memory.c \
	unit-test-keyrings.c \
	unit-test-other.c \
	unit-test-daemon-setup.c 

UNIT_PROMPT = \
	unit-test-login-prompt.c \
	unit-test-keyrings-prompt.c \
	unit-test-daemon-setup.c

UNIT_LIBS =  \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/library/libgnome-keyring.la

include $(top_srcdir)/tests/gtest.make
