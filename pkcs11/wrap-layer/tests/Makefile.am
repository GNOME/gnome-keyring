
INCLUDES = -I. \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/pkcs11 \
	$(GLIB_CFLAGS) \
	$(P11_TESTS_CFLAGS)

LIBS = \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS)

noinst_PROGRAMS = \
	test-create-credential

test_create_credential_SOURCES = \
	test-create-credential.c

test_create_credential_LDADD = \
	$(top_builddir)/pkcs11/wrap-layer/libgkm-wrap-layer.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/ui/libgku-prompt.la \
	$(top_builddir)/egg/libegg.la \
	$(DAEMON_LIBS)