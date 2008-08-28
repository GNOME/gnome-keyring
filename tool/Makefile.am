bin_PROGRAMS= \
	gnome-keyring

INCLUDES=	\
	-DPKCS11_MODULE_PATH=\""$(libdir)/gnome-keyring/gnome-keyring-pkcs11.so"\" 	\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"					\
	-I$(top_srcdir) 								\
	-I$(top_builddir) 								\
	$(GOBJECT_CFLAGS) 								\
	$(GLIB_CFLAGS)
	
gnome_keyring_SOURCES = \
	gkr-tool.c gkr-tool.h \
	gkr-tool-import.c

gnome_keyring_LDADD = \
	$(top_builddir)/gp11/libgp11.la \
	$(GLIB_LIBS) $(GTHREAD_LIBS)
