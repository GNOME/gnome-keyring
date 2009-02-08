
noinst_LTLIBRARIES = \
	libgkr-common.la 

INCLUDES = \
	-I$(top_srcdir) 
	-I$(top_builddir) 

# --------------------------------------------------------------------
# COMMON STUFF COMPILED INTO DAEMON COMPONENTS

libgkr_common_la_CFLAGS = \
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	$(DAEMON_CFLAGS)				\
	$(GTK_CFLAGS) 					\
	$(GLIB_CFLAGS)

libgkr_common_la_SOURCES = \
	gkr-async.c gkr-async.h \
	gkr-cleanup.c gkr-cleanup.h \
	gkr-location.c gkr-location.h \
	gkr-location-watch.c gkr-location-watch.h \
	gkr-unix-signal.c gkr-unix-signal.h \
	gkr-wakeup.c gkr-wakeup.h 

libgkr_common_la_LIBADD = \
	$(top_builddir)/egg/libegg.la \
	$(top_builddir)/egg/libegg-dbus.la \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS)

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
