
UNIT_AUTO = \
	unit-test-keyring-login.c \
	unit-test-keyring-file.c

UNIT_PROMPT = \
	unit-test-login-prompt.c

UNIT_LIBS =  \
	$(top_builddir)/daemon/keyrings/libgkr-keyrings.la \
	$(top_builddir)/daemon/ui/libgkr-ui.la \
	$(top_builddir)/daemon/util/libgkr-daemon-util.la \
	$(top_builddir)/library/libgnome-keyring-common.la \
	$(top_builddir)/egg/libegg-dbus.la \
	$(top_builddir)/egg/libegg.la

EXTRA_DIST = test-data

include $(top_srcdir)/tests/gtest.make
