
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_srcdir)/daemon \
	-I$(top_builddir) \
	-DINTROSPECTDIR=\"$(datadir)/gnome-keyring/introspect\" \
	$(DAEMON_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = libgkr-dbus.la

libgkr_dbus_la_SOURCES = \
	gkd-dbus.c gkd-dbus.h \
	gkd-dbus-environment.c \
	gkd-dbus-private.h \
	gkd-dbus-secrets.c \
	gkd-dbus-service.c \
	gkd-dbus-session.c \
	gkd-dbus-util.c gkd-dbus-util.h \
	gkd-secrets-objects.c gkd-secrets-objects.h \
	gkd-secrets-service.c gkd-secrets-service.h \
	gkd-secrets-session.c gkd-secrets-session.h \
	gkd-secrets-types.h

libgkr_dbus_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

