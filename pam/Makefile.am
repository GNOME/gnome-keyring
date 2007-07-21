
INCLUDES = \
	-I$(top_srcdir) \
	-DGNOME_KEYRING_DAEMON=\""$(bindir)/gnome-keyring-daemon"\" 

lib_LTLIBRARIES = pam_gnome_keyring.la

pam_gnome_keyring_la_SOURCES = \
	gkr-pam-module.c

pam_gnome_keyring_la_LDFLAGS = -module -avoid-version

install-pam: install
	cp $(DESTDIR)$(libdir)/pam_gnome_keyring.so $(PAM_DEST_DIR)/
	$(LN_S) -f pam_gnome_keyring.so $(PAM_DEST_DIR)/pam_gnome_keyring_auth.so
	$(LN_S) -f pam_gnome_keyring.so $(PAM_DEST_DIR)/pam_gnome_keyring_session.so
	
uninstall-pam: 
	rm -f $(PAM_DEST_DIR)/pam_gnome_keyring.so
	rm -f $(PAM_DEST_DIR)/pam_gnome_keyring_auth.so
	rm -f $(PAM_DEST_DIR)/pam_gnome_keyring_session.so
	
