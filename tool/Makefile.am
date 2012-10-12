bin_PROGRAMS= \
	gnome-keyring-@GKR_MAJOR@

INCLUDES=	\
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GTK_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GCK_CFLAGS) \
	$(GCR_CFLAGS) \
	-DGCK_API_SUBJECT_TO_CHANGE

gnome_keyring_@GKR_MAJOR@_SOURCES = \
	gkr-tool.c gkr-tool.h \
	gkr-tool-import.c \
	gkr-tool-trust.c \
	gkr-tool-version.c

gnome_keyring_@GKR_MAJOR@_CFLAGS = \
	-DGCR_API_SUBJECT_TO_CHANGE \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"

gnome_keyring_@GKR_MAJOR@_LDADD = \
	$(top_builddir)/egg/libegg.la \
	$(GCK_LIBS) \
	$(GCR_LIBS) \
	$(GTHREAD_LIBS) \
	$(GCRYPT_LIBS) \
	$(DAEMON_LIBS)

# Install a link from gnome-keyring > gnome-keyring-@GKR_MAJOR@ to maintain compatibility
install-exec-hook:
	@test -e "$(DESTDIR)$(bindir)/gnome-keyring" || (cd $(DESTDIR)$(bindir) && $(LN_S) gnome-keyring-@GKR_MAJOR@ gnome-keyring)
