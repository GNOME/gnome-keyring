noinst_LTLIBRARIES=libgkr-ssh.la

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_builddir) 				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

libgkr_ssh_la_SOURCES = \
	gkr-ssh-daemon.h \
	gkr-ssh-daemon-io.c \
	gkr-ssh-daemon-ops.c \
	gkr-ssh-private.h \
	gkr-ssh-proto.c

libgkr_ssh_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)
