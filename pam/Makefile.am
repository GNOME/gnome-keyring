
INCLUDES = \
	-I$(top_srcdir) \
	-DGNOME_KEYRING_DAEMON=\""$(bindir)/gnome-keyring-daemon"\" 

lib_LTLIBRARIES = pam_gnome_keyring.la

pam_gnome_keyring_la_SOURCES = \
	gkr-pam.h \
	gkr-pam-client.c \
	gkr-pam-module.c \
	gkr-pam-stubs.c

pam_gnome_keyring_la_LIBADD = \
	$(top_builddir)/common/libgkr-module-common.la
	
pam_gnome_keyring_la_LDFLAGS = \
	-module -avoid-version \
	-Wl,--version-script=$(srcdir)/gkr-pam-export.map

install-pam: install
	$(mkinstalldirs) $(DESTDIR)$(PAM_DEST_DIR)
	cp $(DESTDIR)$(libdir)/pam_gnome_keyring.so $(DESTDIR)$(PAM_DEST_DIR)
	( cd $(DESTDIR)$(PAM_DEST_DIR); $(LN_S) -f pam_gnome_keyring.so pam_gnome_keyring_auth.so )
	( cd $(DESTDIR)$(PAM_DEST_DIR); $(LN_S) -f pam_gnome_keyring.so pam_gnome_keyring_session.so )
	
uninstall-pam: 
	rm -f $(PAM_DEST_DIR)/pam_gnome_keyring.so
	rm -f $(PAM_DEST_DIR)/pam_gnome_keyring_auth.so
	rm -f $(PAM_DEST_DIR)/pam_gnome_keyring_session.so
	
