noinst_LTLIBRARIES=libgkr-keyrings.la

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

libgkr_keyrings_la_SOURCES = \
	gkr-keyring.c gkr-keyring.h \
	gkr-keyring-binary.c gkr-keyring-textual.c \
	gkr-keyring-item.c gkr-keyring-item.h \
	gkr-keyrings.c gkr-keyrings.h \
	gkr-keyring-login.c gkr-keyring-login.h 

libgkr_keyrings_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

EXTRA_DIST = \
	file-format.txt 

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
	
