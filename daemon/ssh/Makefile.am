noinst_LTLIBRARIES=libgkr-ssh.la

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

libgkr_ssh_la_SOURCES = \
	gkr-ssh-private.h \
	gkr-ssh-proto.c \
	gkr-ssh-storage.c gkr-ssh-storage.h 

libgkr_ssh_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
