
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
	$(top_builddir)/library/libgnome-keyring.la

UNIT_FLAGS = \
	-DEXTERNAL_TEST
	
include $(top_srcdir)/tests/test.make
