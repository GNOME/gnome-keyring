

# ------------------------------------------------------------------
# DAEMON CODE

noinst_LTLIBRARIES += \
	libgkd-control.la \
	libgkd-control-client.la

libgkd_control_la_SOURCES = \
	daemon/control/gkd-control-server.c \
	daemon/control/gkd-control-client.c \
	daemon/control/gkd-control.h \
	daemon/control/gkd-control-codes.h

libgkd_control_client_la_SOURCES = \
	daemon/control/gkd-control-client.c \
	daemon/control/gkd-control.h

# -------------------------------------------------------------------
# TESTS

noinst_PROGRAMS += \
	frob-control-change \
	frob-control-init \
	frob-control-unlock \
	frob-control-quit

control_LIBS = \
	libgkd-control-client.la \
	libegg-buffer.la \
	libegg-creds.la \
	libegg-secure.la \
	$(GLIB_LIBS)

frob_control_change_SOURCES = \
	daemon/control/frob-control-change.c
frob_control_change_LDADD = $(control_LIBS)

frob_control_init_SOURCES = \
	daemon/control/frob-control-init.c
frob_control_init_LDADD =  $(control_LIBS)

frob_control_quit_SOURCES = \
	daemon/control/frob-control-quit.c
frob_control_quit_LDADD =  $(control_LIBS)

frob_control_unlock_SOURCES = \
	daemon/control/frob-control-unlock.c
frob_control_unlock_LDADD =  $(control_LIBS)
