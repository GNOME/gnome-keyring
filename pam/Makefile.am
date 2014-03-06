
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

# -----------------------------------------------------------------------------
# PAM tests

pam_CONFIGS = \
	pam/fixtures/gnome-keyring-test-auth-start \
	pam/fixtures/gnome-keyring-test-no-start \
	pam/fixtures/gnome-keyring-test-session-start \
	$(NULL)

EXTRA_DIST += pam/fixtures

enable-pam-tests:
	for t in $(notdir $(pam_CONFIGS)); do \
		$(SED_SUBST) $(srcdir)/pam/fixtures/$$t > $(sysconfdir)/pam.d/$$t; \
	done

disable-pam-tests:
	for t in $(notdir $(pam_CONFIGS)); do \
		$(RM) -f $(sysconfdir)/pam.d/$$t; \
	done

noinst_LTLIBRARIES += pam_mock.la

pam_mock_la_SOURCES = pam/mock-pam.c
pam_mock_la_LIBADD = \
	-lpam
pam_mock_la_LDFLAGS = \
	-module -avoid-version \
	-export-symbols-regex 'pam_sm_' \
	-rpath /force/shared

pam_CFLAGS = \
	-DSYSCONFDIR=\"$(sysconfdir)\" \
	$(NULL)

pam_LIBS = \
	libgkd-control-client.la \
	libgkd-test.la \
	libegg.la \
	libegg-test.la \
	$(GIO_LIBS) \
	$(GLIB_LIBS) \
	-lpam

pam_TESTS = \
	test-pam

test_pam_SOURCES = pam/test-pam.c
test_pam_LDADD = $(pam_LIBS)
test_pam_CFLAGS = $(pam_CFLAGS)

check_PROGRAMS += $(pam_TESTS)
TESTS += $(pam_TESTS)
