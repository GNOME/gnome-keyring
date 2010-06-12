
TESTING_FILES = \
	mock-secret-store.c \
	test-create-credential.c \
	test-login-auto.c \
	test-login-hints.c \
	test-login-keyring.c \
	test-login-specific.c \
	test-login-user.c

TESTING_LIBS = \
	$(top_builddir)/pkcs11/wrap-layer/libgkm-wrap-layer.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/ui/libgku-prompt.la \
	$(top_builddir)/egg/libegg.la

include $(top_srcdir)/testing/testing.make