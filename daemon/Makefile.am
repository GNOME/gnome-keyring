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
	$(GTHREAD_CFLAGS)				\
	$(GLIB_CFLAGS)

gnome_keyring_daemon_SOURCES = \
	gkr-daemon.c \
	gkr-daemon.h \
	gkr-daemon-dbus.c \
	gkr-daemon-io.c \
	gkr-daemon-ops.c

gnome_keyring_daemon_LDADD = \
	$(top_builddir)/ssh/libgkr-ssh.la \
	$(top_builddir)/pk/libgkr-pk.la \
	$(top_builddir)/keyrings/libgkr-keyrings.la \
	$(top_builddir)/ui/libgkr-ui.la \
	$(top_builddir)/library/libgnome-keyring-common.la \
	$(top_builddir)/common/libgkr-common.la \
	$(DAEMON_LIBS) \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(DAEMON_LIBS) \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)
