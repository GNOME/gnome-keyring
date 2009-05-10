
noinst_LTLIBRARIES=libgkr-daemon-util.la

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/daemon 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

libgkr_daemon_util_la_SOURCES = \
	gkr-daemon-async.c gkr-daemon-async.h \
	gkr-daemon-util.c gkr-daemon-util.h \
	gkr-location.c gkr-location.h \
	gkr-location-watch.c gkr-location-watch.h
	
libgkr_daemon_util_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
