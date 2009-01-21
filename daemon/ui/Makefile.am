libexec_PROGRAMS= \
	gnome-keyring-ask

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/daemon 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)					\
	$(GTK_CFLAGS)
	
gnome_keyring_ask_SOURCES = \
	gkr-ask-tool.c gkr-ask-tool.h \
	gkr-ask-tool-widgets.c \
	gkr-ask-request.h
	
gnome_keyring_ask_LDADD = \
	$(top_builddir)/egg/libegg-secure.la \
	$(top_builddir)/egg/libegg-secure-entry.la \
	$(GTK_LIBS)

noinst_LTLIBRARIES=libgkr-ui.la

BUILT_SOURCES = \
	gkr-ask-marshal.c gkr-ask-marshal.h

libgkr_ui_la_SOURCES = \
	gkr-ask-request.c gkr-ask-request.h \
	gkr-ask-daemon.c gkr-ask-daemon.h \
	$(BUILT_SOURCES)

libgkr_ui_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

gkr-ask-marshal.h: gkr-ask-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=gkr_ask_marshal > $@

gkr-ask-marshal.c: gkr-ask-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gkr-ask-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=gkr_ask_marshal >> $@

EXTRA_DIST = gkr-ask-marshal.list
