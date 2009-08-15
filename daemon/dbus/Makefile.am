
INCLUDES = \
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/daemon 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = libgkr-dbus.la

libgkr_dbus_la_SOURCES = \
	gkd-dbus.c gkd-dbus.h \
	gkd-dbus-environment.c \
	gkd-dbus-private.h \
	gkd-dbus-service.c \
	gkd-dbus-session.c

libgkr_dbus_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

