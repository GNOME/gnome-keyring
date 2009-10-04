INCLUDES= \
	-DPREFIX=\""$(prefix)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(DAEMON_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GTK_CFLAGS)

# ------------------------------------------------------------------
# UI BUILDER
#

uidir = $(datadir)/gnome-keyring/ui/

ui_DATA = \
	gku-prompt.ui

# ------------------------------------------------------------------
# PROMPT TOOL
#

libexec_PROGRAMS= \
	gnome-keyring-prompt

gnome_keyring_prompt_SOURCES = \
	gku-prompt-tool.c

gnome_keyring_prompt_LDADD = \
	$(top_builddir)/egg/libegg.la \
	$(GTK_LIBS)

gnome_keyring_prompt_CFLAGS = \
	-DUIDIR=\""$(uidir)"\"
