
noinst_LTLIBRARIES = \
	libgkr-daemon-common.la \
	libgkr-module-common.la

INCLUDES = \
	-I$(top_srcdir) 
	-I$(top_builddir) 

# --------------------------------------------------------------------
# COMMON STUFF COMPILED INTO DAEMON 

libgkr_daemon_common_la_CFLAGS = \
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	$(DAEMON_CFLAGS)				\
	$(GTK_CFLAGS) 					\
	$(GLIB_CFLAGS)

libgkr_daemon_common_la_SOURCES = \
	gkr-async.c \
	gkr-async.h \
	gkr-buffer.c \
	gkr-buffer.h \
	gkr-cleanup.c \
	gkr-cleanup.h \
	gkr-dbus.c \
	gkr-dbus.h \
	gkr-location.c \
	gkr-location.h \
	gkr-secure-memory.c \
	gkr-secure-memory.h \
	gkr-unix-signal.c \
	gkr-unix-signal.h \
	gkr-wakeup.c \
	gkr-wakeup.h 

libgkr_daemon_common_la_LIBADD = \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS)

# --------------------------------------------------------------------
# COMMON STUFF COMPILED INTO LOADABLE MODULES

libgkr_module_common_la_SOURCES = \
	gkr-buffer.c \
	gkr-buffer.h \
	gkr-secure-memory.c \
	gkr-secure-memory.h


