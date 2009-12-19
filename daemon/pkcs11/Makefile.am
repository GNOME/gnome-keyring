
INCLUDES = \
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/daemon 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

DAEMON_SRCS = \
	gkd-pkcs11-auth.c gkd-pkcs11-auth.h \
	gkd-pkcs11-data.c gkd-pkcs11-data.h \
	gkd-pkcs11.c gkd-pkcs11.h

noinst_LTLIBRARIES = libgkd-pkcs11.la

libgkd_pkcs11_la_SOURCES = $(DAEMON_SRCS)

libgkd_pkcs11_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

