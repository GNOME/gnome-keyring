
EXTRA_DIST = \
	gkr-pkcs11-module-export.map \
	pkcs11.h \
	pkcs11n.h 

# ------------------------------------------------------------------------------
# The pkcs11 module 

moduledir = $(libdir)/gnome-keyring/

MODULE_SRCS = \
	gkr-pkcs11-module.c \
	gkr-pkcs11-message.c gkr-pkcs11-message.h \
	gkr-pkcs11-mechanisms.h gkr-pkcs11-calls.h 

module_LTLIBRARIES = gnome-keyring-pkcs11.la

gnome_keyring_pkcs11_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

gnome_keyring_pkcs11_la_CFLAGS = \
	-I. \
	-I$(top_srcdir)

gnome_keyring_pkcs11_la_SOURCES = $(MODULE_SRCS)

gnome_keyring_pkcs11_la_LIBADD = \
	$(top_builddir)/common/libgkr-module-common.la 

# ------------------------------------------------------------------------------
# The pkcs11 parts in the daemon. Currently these are built into 
# their own binary for testing purposes.
# 

INCLUDES = \
	-I$(top_srcdir) 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

DAEMON_SRCS = \
	gkr-pkcs11-calls.h \
	gkr-pkcs11-daemon.c gkr-pkcs11-daemon.h \
	gkr-pkcs11-daemon-session.c \
	gkr-pkcs11-dsa.c gkr-pkcs11-dsa.h \
	gkr-pkcs11-mechanisms.h \
	gkr-pkcs11-message.c gkr-pkcs11-message.h \
	gkr-pkcs11-rsa.c gkr-pkcs11-rsa.h

noinst_LTLIBRARIES = libgkr-pkcs11.la

libgkr_pkcs11_la_SOURCES = $(DAEMON_SRCS)

libgkr_pkcs11_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

