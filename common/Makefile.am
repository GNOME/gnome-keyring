
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
	$(GTK_CFLAGS) 					\
	$(GLIB_CFLAGS)

libgkr_daemon_common_la_SOURCES = \
	gkr-buffer.c \
	gkr-buffer.h \
	gkr-cleanup.c \
	gkr-cleanup.h \
	gkr-secure-memory.c \
	gkr-secure-memory.h

libgkr_daemon_common_la_LIBADD = \
	$(GLIB_LIBS)

# --------------------------------------------------------------------
# COMMON STUFF COMPILED INTO LOADABLE MODULES

libgkr_module_common_la_SOURCES = \
	gkr-buffer.c \
	gkr-buffer.h \
	gkr-secure-memory.c \
	gkr-secure-memory.h


