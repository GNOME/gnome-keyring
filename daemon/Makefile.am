if WITH_SSH
SSH_DIR = ssh
else
SSH_DIR =
endif

SUBDIRS = \
	ui \
	keyrings \
	pkix \
	pk \
	pkcs11 \
	$(SSH_DIR) \
	data 

bin_PROGRAMS= \
	gnome-keyring-daemon

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/daemon 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS)				\
	$(GTHREAD_CFLAGS)				\
	$(GLIB_CFLAGS)

gnome_keyring_daemon_SOURCES = \
	gkr-daemon.c \
	gkr-daemon.h \
	gkr-daemon-dbus.c \
	gkr-daemon-io.c \
	gkr-daemon-ops.c

gnome_keyring_daemon_LDADD = \
	$(top_builddir)/daemon/ssh/libgkr-ssh.la \
	$(top_builddir)/daemon/pkcs11/libgkr-pkcs11.la \
	$(top_builddir)/daemon/pk/libgkr-pk.la \
	$(top_builddir)/daemon/keyrings/libgkr-keyrings.la \
	$(top_builddir)/daemon/ui/libgkr-ui.la \
	$(top_builddir)/library/libgnome-keyring-common.la \
	$(top_builddir)/common/libgkr-common.la \
	$(DAEMON_LIBS) \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(DAEMON_LIBS) \
	$(GOBJECT_LIBS) \
	$(GLIB_LIBS)

EXTRA_DIST = org.gnome.keyring.service.in
CLEANFILES = org.gnome.keyring.service

if WITH_DBUS
servicedir       = $(DBUS_SERVICES_DIR)
service_in_files = org.gnome.keyring.service.in
service_DATA     = $(service_in_files:.service.in=.service)

$(service_DATA): $(service_in_files) Makefile
	@sed -e "s|\@BINDIR\@|$(bindir)|" $< > $@
endif

