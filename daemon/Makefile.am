
bin_PROGRAMS += \
	gnome-keyring-daemon

gnome_keyring_daemon_SOURCES = \
	daemon/gkd-glue.c \
	daemon/gkd-glue.h \
	daemon/gkd-main.c \
	daemon/gkd-main.h \
	daemon/gkd-capability.c \
	daemon/gkd-capability.h \
	daemon/gkd-pkcs11.c \
	daemon/gkd-pkcs11.h \
	daemon/gkd-util.c \
	daemon/gkd-util.h \
	$(NULL)
gnome_keyring_daemon_LDADD = \
	libgkd-dbus.la \
	libgkd-login.la \
	libgkd-control.la \
	libgkd-ssh-agent.la \
	libgkd-gpg-agent.la \
	libgkm-wrap-layer.la \
	libgkm-rpc-layer.la \
	libgkm-secret-store.la \
	libgkm-ssh-store.la \
	libgkm-gnome2-store.la \
	libgkm-xdg-store.la \
	libgkm.la \
	libegg-dbus.la \
	$(DAEMON_LIBS)

service_in_files = \
	daemon/org.gnome.keyring.service.in \
	daemon/org.freedesktop.secrets.service.in
servicedir = $(DBUS_SERVICES_DIR)
service_DATA = $(service_in_files:.service.in=.service)

desktopdir = $(sysconfdir)/xdg/autostart
desktop_in_in_files = \
	daemon/gnome-keyring-pkcs11.desktop.in.in \
	daemon/gnome-keyring-secrets.desktop.in.in \
	daemon/gnome-keyring-ssh.desktop.in.in \
	daemon/gnome-keyring-gpg.desktop.in.in
desktop_in_files = $(desktop_in_in_files:.desktop.in.in=.desktop.in)
desktop_DATA = $(desktop_in_files:.desktop.in=.desktop)

EXTRA_DIST += \
	$(service_in_files) \
	$(desktop_in_in_files)

CLEANFILES += \
	$(service_DATA) \
	$(desktop_DATA)

# -------------------------------------------------------------------
# TESTS

noinst_LTLIBRARIES += libgkd-test.la

libgkd_test_la_SOURCES = \
	daemon/gkd-test.c \
	daemon/gkd-test.h

daemon_CFLAGS = \
	$(DBUS_CFLAGS) \
	$(GCR_CFLAGS)

daemon_LIBS = \
	libgkd-control-client.la \
	libgkd-test.la \
	libegg.la \
	libegg-test.la \
	$(GCR_BASE_LIBS) \
	$(GIO_LIBS) \
	$(GLIB_LIBS)

daemon_TESTS = \
	test-startup \
	test-shutdown

test_startup_SOURCES = daemon/test-startup.c
test_startup_LDADD = $(daemon_LIBS)
test_statrup_CFLAGS = $(daemon_CFLAGS)

test_shutdown_SOURCES = daemon/test-shutdown.c
test_shutdown_LDADD = $(daemon_LIBS)
test_shutdown_CFLAGS = $(daemon_CFLAGS)

check_PROGRAMS += $(daemon_TESTS)
TESTS += $(daemon_TESTS)
