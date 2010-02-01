
if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR =
endif

SUBDIRS = . $(TESTS_DIR)

INCLUDES= \
	-DPREFIX=\""$(prefix)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS)

# ------------------------------------------------------------------
# UI BUILDER
#

uidir = $(datadir)/gnome-keyring/ui/

ui_DATA = \
	gkd-prompt.ui

# ------------------------------------------------------------------
# DAEMON CODE

noinst_LTLIBRARIES = libgkd-prompt.la

BUILT_SOURCES = \
	gkd-prompt-marshal.c gkd-prompt-marshal.h

libgkd_prompt_la_SOURCES = \
	gkd-prompt.c gkd-prompt.h \
	gkd-prompt-util.c gkd-prompt-util.h \
	$(BUILT_SOURCES)

libgkd_prompt_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

gkd-prompt-marshal.h: gkd-prompt-marshal.list $(GLIB_GENMARSHAL)
	$(GLIB_GENMARSHAL) $< --header --prefix=gkd_prompt_marshal > $@

gkd-prompt-marshal.c: gkd-prompt-marshal.list $(GLIB_GENMARSHAL)
	echo "#include \"gkd-prompt-marshal.h\"" > $@ && \
	$(GLIB_GENMARSHAL) $< --body --prefix=gkd_prompt_marshal >> $@

EXTRA_DIST = \
	gkd-prompt-marshal.list \
	$(ui_DATA)

# ------------------------------------------------------------------
# PROMPT TOOL
#

libexec_PROGRAMS= \
	gnome-keyring-prompt

gnome_keyring_prompt_SOURCES = \
	gkd-prompt-tool.c \
	gkd-prompt-util.c gkd-prompt-util.h

gnome_keyring_prompt_LDADD = \
	$(top_builddir)/egg/libegg-prompt.la \
	$(top_builddir)/egg/libegg-entry-buffer.la \
	$(top_builddir)/gcr/libgcr.la \
	$(LIBGCRYPT_LIBS) \
	$(GTK_LIBS)

gnome_keyring_prompt_CFLAGS = \
	-DUIDIR=\""$(uidir)"\" \
	-DGCR_API_SUBJECT_TO_CHANGE \
	$(LIBGCRYPT_CFLAGS) \
	$(GTK_CFLAGS)
