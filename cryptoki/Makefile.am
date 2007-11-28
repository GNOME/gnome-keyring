
# ------------------------------------------------------------------------------
# The cryptoki module 

MODULE_SRCS = \
	gkr-cryptoki-module.c \
	gkr-cryptoki-message.c gkr-cryptoki-message.h \
	gkr-cryptoki-mechanisms.h gkr-cryptoki-calls.h 

lib_LTLIBRARIES = gnome-keyring-cryptoki.la

gnome_keyring_cryptoki_la_LDFLAGS = \
	-module \
	-version-info 0:0:0 \
	-Wl,--no-undefined \
	-Wl,--version-script=$(srcdir)/gkr-cryptoki-module-export.map

gnome_keyring_cryptoki_la_CFLAGS = \
	-I. \
	-I$(top_srcdir)

gnome_keyring_cryptoki_la_SOURCES = $(MODULE_SRCS)

gnome_keyring_cryptoki_la_LIBADD = \
	$(top_builddir)/common/libgkr-module-common.la 

EXTRA_DIST = \
	gkr-cryptoki-module-export.map


# ------------------------------------------------------------------------------
# The cryptoki parts in the daemon. Currently these are built into 
# their own binary for testing purposes.
# 

DAEMON_SRCS = \
	gkr-cryptoki-calls.h \
	gkr-cryptoki-daemon.c gkr-cryptoki-daemon.h \
	gkr-cryptoki-daemon-session.c \
	gkr-cryptoki-mechanisms.h \
	gkr-cryptoki-message.c gkr-cryptoki-message.h 

noinst_PROGRAMS = gnome-keyring-cryptoki-test-daemon

gnome_keyring_cryptoki_test_daemon_CFLAGS = \
	-I. \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GTHREAD_CFLAGS)
gnome_keyring_cryptoki_test_daemon_SOURCES = \
	$(DAEMON_SRCS) \
	gkr-cryptoki-daemon-test.c
gnome_keyring_cryptoki_test_daemon_LDADD = \
	$(top_builddir)/pk/libgkr-pk.la \
	$(top_builddir)/pkix/libgkr-pkix.la \
	$(top_builddir)/ui/libgkr-ui.la \
	$(top_builddir)/keyrings/libgkr-keyrings.la \
	$(top_builddir)/library/libgnome-keyring-common.la \
	$(top_builddir)/common/libgkr-common.la \
	$(DAEMON_LIBS) \
	$(GLIB_LIBS) \
	$(GOBJECT_CFLAGS) \
	$(GTHREAD_LIBS)

