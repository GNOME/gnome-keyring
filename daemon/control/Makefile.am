
INCLUDES= \
	-DPREFIX=\""$(prefix)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-I$(top_srcdir) \
	-I$(top_srcdir)/daemon \
	-I$(top_builddir) \
	$(GLIB_CFLAGS)

LIBS = \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(P11_TESTS_LIBS)

# ------------------------------------------------------------------
# DAEMON CODE

noinst_LTLIBRARIES = \
	libgkd-control.la \
	libgkd-control-client.la

libgkd_control_la_SOURCES = \
	gkd-control-server.c gkd-control-client.c \
	gkd-control.h gkd-control-codes.h

libgkd_control_client_la_SOURCES = \
	gkd-control-client.c gkd-control.h

# -------------------------------------------------------------------
# TESTS

noinst_PROGRAMS= \
	frob-control-change \
	frob-control-init \
	frob-control-unlock \
	frob-control-quit

frob_control_change_SOURCES = \
	frob-control-change.c

frob_control_change_LDADD = \
	$(top_builddir)/daemon/control/libgkd-control-client.la \
	$(top_builddir)/egg/libegg-buffer.la \
	$(top_builddir)/egg/libegg-creds.la \
	$(top_builddir)/egg/libegg-secure.la

frob_control_init_SOURCES = \
	frob-control-init.c

frob_control_init_LDADD = \
	$(top_builddir)/daemon/control/libgkd-control-client.la \
	$(top_builddir)/egg/libegg-buffer.la \
	$(top_builddir)/egg/libegg-creds.la \
	$(top_builddir)/egg/libegg-secure.la

frob_control_quit_SOURCES = \
	frob-control-quit.c

frob_control_quit_LDADD = \
	$(top_builddir)/daemon/control/libgkd-control-client.la \
	$(top_builddir)/egg/libegg-buffer.la \
	$(top_builddir)/egg/libegg-creds.la \
	$(top_builddir)/egg/libegg-secure.la

frob_control_unlock_SOURCES = \
	frob-control-unlock.c

frob_control_unlock_LDADD = \
	$(top_builddir)/daemon/control/libgkd-control-client.la \
	$(top_builddir)/egg/libegg-buffer.la \
	$(top_builddir)/egg/libegg-creds.la \
	$(top_builddir)/egg/libegg-secure.la