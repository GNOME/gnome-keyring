
# ------------------------------------------------------------------------------
# The pkcs11 module 

MODULE_SRCS = \
	gkr-pkcs11-module.c \
	gkr-pkcs11-message.c gkr-pkcs11-message.h \
	gkr-pkcs11-mechanisms.h gkr-pkcs11-calls.h 

lib_LTLIBRARIES = gnome-keyring-pkcs11.la

gnome_keyring_pkcs11_la_LDFLAGS = \
	-module \
	-version-info 0:0:0 \
	-Wl,--no-undefined \
	-Wl,--version-script=$(srcdir)/gkr-pkcs11-module-export.map

gnome_keyring_pkcs11_la_CFLAGS = \
	-I. \
	-I$(top_srcdir)

gnome_keyring_pkcs11_la_SOURCES = $(MODULE_SRCS)

gnome_keyring_pkcs11_la_LIBADD = \
	$(top_builddir)/common/libgkr-module-common.la 

EXTRA_DIST = \
	gkr-pkcs11-module-export.map \
	pkcs11.h \
	pkcs11n.h 


# ------------------------------------------------------------------------------
# The pkcs11 parts in the daemon. Currently these are built into 
# their own binary for testing purposes.
# 

DAEMON_SRCS = \
	gkr-pkcs11-calls.h \
	gkr-pkcs11-daemon.c gkr-pkcs11-daemon.h \
	gkr-pkcs11-daemon-session.c \
	gkr-pkcs11-mechanisms.h \
	gkr-pkcs11-message.c gkr-pkcs11-message.h 

noinst_PROGRAMS = gnome-keyring-pkcs11-test-daemon

gnome_keyring_pkcs11_test_daemon_CFLAGS = \
	-I. \
	-I$(top_srcdir) \
	$(GLIB_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GTHREAD_CFLAGS)
gnome_keyring_pkcs11_test_daemon_SOURCES = \
	$(DAEMON_SRCS) \
	gkr-pkcs11-daemon-test.c
gnome_keyring_pkcs11_test_daemon_LDADD = \
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

