
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
	gkd-secret-create.c gkd-secret-create.h \
	gkd-secret-error.c gkd-secret-error.h \
	gkd-secret-objects.c gkd-secret-objects.h \
	gkd-secret-property.c gkd-secret-property.h \
	gkd-secret-prompt.c gkd-secret-prompt.h \
	gkd-secret-secret.c gkd-secret-secret.h \
	gkd-secret-service.c gkd-secret-service.h \
	gkd-secret-session.c gkd-secret-session.h \
	gkd-secret-types.h \
	gkd-secret-unlock.c gkd-secret-unlock.h \
	gkd-secret-util.c gkd-secret-util.h

libgkr_dbus_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

