bin_PROGRAMS= \
	gnome-keyring-daemon

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS)				\
	$(GLIB_CFLAGS)

LIBADD_SOURCE = mkdtemp.c mkdtemp.h

gnome_keyring_daemon_SOURCES = \
	gkr-daemon.c \
	gkr-daemon.h \
	gkr-daemon-dbus.c \
	gkr-daemon-io.c \
	gkr-daemon-ops.c

gnome_keyring_daemon_LDADD = \
	$(top_builddir)/library/libgnome-keyring-common.la \
	$(top_builddir)/keyrings/libgnome-keyring-keyrings.la \
	$(top_builddir)/ui/libdaemon-ui-component.la \
	$(top_builddir)/common/libgkr-daemon-common.la \
	@LIBOBJS@ \
	$(DAEMON_LIBS) \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)

EXTRA_DIST = \
	$(LIBADD_SOURCE) 

