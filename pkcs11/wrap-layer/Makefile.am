
noinst_LTLIBRARIES = \
	libgkm-wrap-layer.la

INCLUDES = -I. \
	-I$(top_srcdir) \
	-I$(top_builddir) \
	-I$(top_srcdir)/pkcs11 \
	-DSRCDIR="\"@abs_srcdir@\"" \
	$(GCR_BASE_CFLAGS) \
	-DGCR_API_SUBJECT_TO_CHANGE

# ------------------------------------------------------------------------------
# The code

libgkm_wrap_layer_la_SOURCES = \
	gkm-wrap-layer.c gkm-wrap-layer.h \
	gkm-wrap-login.c gkm-wrap-login.h \
	gkm-wrap-prompt.c gkm-wrap-prompt.h

libgkm_wrap_layer_la_LIBADD = \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(GIO_LIBS)

libgkm_wrap_layer_la_CFLAGS = \
	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GIO_CFLAGS)

# ------------------------------------------------------------------------------
# TESTS

LDADD = \
	$(top_builddir)/pkcs11/wrap-layer/libgkm-wrap-layer.la \
	libgkm-mock-secret-store.a \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(top_builddir)/egg/libegg.la \
	$(GCR_BASE_LIBS) \
	$(GLIB_LIBS)

TEST_PROGS = \
	test-create-credential \
	test-init-pin \
	test-login-auto \
	test-login-hints \
	test-login-keyring \
	test-login-specific \
	test-login-user \
	test-set-pin

check_PROGRAMS = $(TEST_PROGS)

test: $(TEST_PROGS) $(CHECK_PROGS)
	gtester --verbose -m $(TEST_MODE) --g-fatal-warnings $(TEST_PROGS)

check-local: test

all-local: $(check_PROGRAMS)

noinst_LIBRARIES = libgkm-mock-secret-store.a

libgkm_mock_secret_store_a_SOURCES = \
	mock-secret-store.c