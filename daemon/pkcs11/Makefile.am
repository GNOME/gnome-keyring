
INCLUDES = \
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/daemon 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

DAEMON_SRCS = \
	gkr-pkcs11-auth.c gkr-pkcs11-auth.h gkr-pkcs11-auth-ep.c \
	gkr-pkcs11-daemon.c gkr-pkcs11-daemon.h

noinst_LTLIBRARIES = libgkr-pkcs11.la

libgkr_pkcs11_la_SOURCES = $(DAEMON_SRCS)

libgkr_pkcs11_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

