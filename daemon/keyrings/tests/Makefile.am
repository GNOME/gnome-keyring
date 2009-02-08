
UNIT_AUTO = \
	unit-test-keyring-login.c \
	unit-test-keyring-file.c \
	$(top_srcdir)/daemon/gkr-daemon-util.c \
	$(top_srcdir)/daemon/gkr-daemon-util.h

UNIT_PROMPT = \
	unit-test-login-prompt.c \
	$(top_srcdir)/daemon/gkr-daemon-util.c \
	$(top_srcdir)/daemon/gkr-daemon-util.h

UNIT_LIBS =  \
	$(top_builddir)/daemon/keyrings/libgkr-keyrings.la \
	$(top_builddir)/daemon/ui/libgkr-ui.la \
	$(top_builddir)/library/libgnome-keyring-common.la \
	$(top_builddir)/common/libgkr-common.la

EXTRA_DIST = test-data

include $(top_srcdir)/tests/test.make
