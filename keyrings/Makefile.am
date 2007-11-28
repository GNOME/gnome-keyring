noinst_LTLIBRARIES=libgkr-keyrings.la

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_builddir) 				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

libgkr_keyrings_la_SOURCES = \
	gkr-keyring.c gkr-keyring.h \
	gkr-keyring-item.c gkr-keyring-item.h \
	gkr-keyrings.c gkr-keyrings.h \
	gkr-keyrings-auto-unlock.c gkr-keyrings-auto-unlock.h 

libgkr_keyrings_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

EXTRA_DIST = \
	file-format.txt 
