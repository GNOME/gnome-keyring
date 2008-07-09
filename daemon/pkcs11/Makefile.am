
INCLUDES = \
	-I$(top_srcdir) 				\
	-I$(top_srcdir)/daemon 				\
	-I$(top_builddir) 				\
	$(DAEMON_CFLAGS)				\
	$(GOBJECT_CFLAGS) 				\
	$(GLIB_CFLAGS)

DAEMON_SRCS = \
	gkr-pkcs11-daemon.c gkr-pkcs11-daemon.h \
	gkr-pkcs11-daemon-session.c \
	gkr-pkcs11-dsa.c gkr-pkcs11-dsa.h \
	$(top_srcdir)/pkcs11/gkr-pkcs11-message.c \
	gkr-pkcs11-rsa.c gkr-pkcs11-rsa.h

noinst_LTLIBRARIES = libgkr-pkcs11.la

libgkr_pkcs11_la_SOURCES = $(DAEMON_SRCS)

libgkr_pkcs11_la_LIBADD = \
	$(GLIB_LIBS) \
	$(GOBJECT_LIBS)

