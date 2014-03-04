
pamlibdir = $(PAM_DEST_DIR)
pamlib_LTLIBRARIES = pam_gnome_keyring.la

pam_gnome_keyring_la_SOURCES = \
	pam/gkr-pam.h \
	pam/gkr-pam-client.c \
	pam/gkr-pam-module.c \
	pam/gkr-pam-stubs.c
pam_gnome_keyring_la_CFLAGS = \
	-DGNOME_KEYRING_DAEMON=\""$(bindir)/gnome-keyring-daemon"\"
pam_gnome_keyring_la_LIBADD = \
	libegg-buffer.la \
	libegg-creds.la \
	libegg-secure.la \
	$(LIBSELINUX) \
	-lpam
pam_gnome_keyring_la_LDFLAGS = \
	-module -avoid-version \
	-export-symbols-regex 'pam_sm_'
