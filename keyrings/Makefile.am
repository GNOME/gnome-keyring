noinst_LTLIBRARIES=libgnome-keyring-keyrings.la

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_builddir) 				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

libgnome_keyring_keyrings_la_SOURCES = \
	gkr-keyring.c gkr-keyring.h \
	gkr-keyring-item.c gkr-keyring-item.h

libgnome_keyring_keyrings_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)
