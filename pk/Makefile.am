noinst_LTLIBRARIES=libgkr-pk.la

INCLUDES=	\
	-DPREFIX=\""$(prefix)"\" 			\
	-DBINDIR=\""$(bindir)"\" 			\
	-DLIBEXECDIR=\""$(libexecdir)"\"		\
	-DGNOMELOCALEDIR=\""$(datadir)/locale"\"	\
	-I$(top_srcdir) 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

libgkr_pk_la_SOURCES = \
	gkr-pk-cert.c gkr-pk-cert.h \
	gkr-pk-index.c gkr-pk-index.h \
	gkr-pk-netscape-trust.c gkr-pk-netscape-trust.h \
	gkr-pk-object.c gkr-pk-object.h \
	gkr-pk-object-manager.c gkr-pk-object-manager.h \
	gkr-pk-object-storage.c gkr-pk-object-storage.h \
	gkr-pk-places.h \
	gkr-pk-privkey.c gkr-pk-privkey.h \
	gkr-pk-pubkey.c gkr-pk-pubkey.h \
	gkr-pk-util.c gkr-pk-util.h

libgkr_pk_la_LIBADD = \
	$(top_builddir)/ui/libgkr-ui.la \
	$(top_builddir)/pkix/libgkr-pkix.la \
	$(top_builddir)/common/libgkr-common.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS)

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
