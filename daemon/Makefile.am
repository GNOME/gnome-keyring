bin_PROGRAMS= \
	gnome-keyring-daemon

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/library/			\
	-I$(top_builddir) 				\
	$(GTK_CFLAGS) 					\
	$(GOBJECT_CFLAGS)				\
	$(GLIB_CFLAGS)

LIBADD_SOURCE = mkdtemp.c mkdtemp.h

gnome_keyring_daemon_SOURCES = \
	gnome-keyring-daemon.c \
	gnome-keyring-daemon.h \
	gnome-keyring-daemon-io.c \
	gnome-keyring-daemon-dbus.c

gnome_keyring_daemon_LDADD = \
	$(top_builddir)/common/libgkr-daemon-common.la \
	$(top_builddir)/library/libgnome-keyring-common.la \
	$(top_builddir)/keyrings/libgnome-keyring-keyrings.la \
	$(top_builddir)/ui/libdaemon-ui-component.la \
	@LIBOBJS@ \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)

EXTRA_DIST = \
	$(LIBADD_SOURCE) 

