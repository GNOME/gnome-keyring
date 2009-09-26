bin_PROGRAMS= \
	gnome-keyring

INCLUDES=	\
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GTK_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS)
	
gnome_keyring_SOURCES = \
	gkr-tool.c gkr-tool.h \
	gkr-tool-import.c
	
gnome_keyring_CFLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"

gnome_keyring_LDADD = \
	$(top_builddir)/gp11/libgp11.la \
	$(top_builddir)/gcr/libgcr.la \
	$(top_builddir)/egg/libegg.la \
	$(GTHREAD_LIBS) \
	$(GTK_LIBS) \
	$(GCRYPT_LIBS) \
	$(LIBTASN1_LIBS) \
	$(DAEMON_LIBS)
