
INCLUDES = \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS)

noinst_LTLIBRARIES = libgkd-prompt.la

BUILT_SOURCES = \
	gkd-prompt-marshal.c gkd-prompt-marshal.h

libgkd_prompt_la_SOURCES = \
	gkd-prompt.c gkd-prompt.h \
	$(BUILT_SOURCES)

libgkd_prompt_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

gkd-prompt-marshal.h: gkd-prompt-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=gkd_prompt_marshal > $@

gkd-prompt-marshal.c: gkd-prompt-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gkd-prompt-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=gkd_prompt_marshal >> $@

EXTRA_DIST = gkd-prompt-marshal.list
