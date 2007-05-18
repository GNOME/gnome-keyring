libexec_PROGRAMS= \
	gnome-keyring-ask

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/library/			\
	-I$(top_builddir) 				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

gnome_keyring_ask_SOURCES = \
	gkr-ask-tool.c gkr-ask-request.h
	
gnome_keyring_ask_CFLAGS = \
	$(GTK_CFLAGS)

gnome_keyring_ask_LDADD = \
	$(GTK_LIBS)

noinst_LTLIBRARIES=libdaemon-ui-component.la

BUILT_SOURCES = \
	gkr-ask-marshal.c gkr-ask-marshal.h

libdaemon_ui_component_la_SOURCES = \
	gkr-ask-request.c gkr-ask-request.h \
	gkr-ask-daemon.c gkr-ask-daemon.h \
	$(BUILT_SOURCES)

libdaemon_ui_component_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

gkr-ask-marshal.h: gkr-ask-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=gkr_ask_marshal > $@

gkr-ask-marshal.c: gkr-ask-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gkr-ask-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=gkr_ask_marshal >> $@

EXTRA_DIST = gkr-ask-marshal.list
