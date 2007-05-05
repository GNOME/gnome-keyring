bin_PROGRAMS= \
	gnome-keyring-daemon

libexec_PROGRAMS= \
	gnome-keyring-ask

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 					\
	-I$(top_srcdir)/library/			\
	-I$(top_builddir) 				\
	$(GTK_CFLAGS) 					\
	$(GLIB_CFLAGS)

LIBADD_SOURCE = mkdtemp.c mkdtemp.h

gnome_keyring_daemon_SOURCES = \
	gnome-keyring-daemon.c \
	gnome-keyring-daemon-file.c \
	gnome-keyring-daemon.h \
	gnome-keyring-daemon-io.c \
	gnome-keyring-daemon-dbus.c

gnome_keyring_daemon_LDADD = \
	$(top_builddir)/library/libgnome-keyring-common.la \
	@LIBOBJS@ \
	$(GLIB_LIBS)

gnome_keyring_ask_SOURCES = \
	gnome-keyring-ask.c

gnome_keyring_ask_LDADD = \
	$(GTK_LIBS)

EXTRA_DIST = \
	$(LIBADD_SOURCE) 

