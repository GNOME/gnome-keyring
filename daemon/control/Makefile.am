
INCLUDES= \
	-DPREFIX=\""$(prefix)"\" \
	-DBINDIR=\""$(bindir)"\" \
	-DLIBEXECDIR=\""$(libexecdir)"\" \
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\" \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	$(GLIB_CFLAGS)

# ------------------------------------------------------------------
# DAEMON CODE

noinst_LTLIBRARIES = libgkd-control.la

libgkd_control_la_SOURCES = \
	gkd-control.c gkd-control.h

libgkd_control_la_LIBADD = \
	$(GLIB_LIBS)
