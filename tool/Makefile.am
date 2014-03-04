bin_PROGRAMS += \
	gnome-keyring-@GKR_MAJOR@

gnome_keyring_@GKR_MAJOR@_SOURCES = \
	tool/gkr-tool.c \
	tool/gkr-tool.h \
	tool/gkr-tool-import.c \
	tool/gkr-tool-trust.c \
	tool/gkr-tool-version.c
gnome_keyring_@GKR_MAJOR@_CFLAGS = \
	$(GTK_CFLAGS) \
	$(GOBJECT_CFLAGS) \
	$(GCK_CFLAGS) \
	$(GCR_CFLAGS)
gnome_keyring_@GKR_MAJOR@_LDADD = \
	libegg.la \
	$(GCK_LIBS) \
	$(GCR_LIBS) \
	$(GTK_LIBS) \
	$(GTHREAD_LIBS) \
	$(GCRYPT_LIBS) \
	$(DAEMON_LIBS)
