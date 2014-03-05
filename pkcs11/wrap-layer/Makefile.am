
noinst_LTLIBRARIES += \
	libgkm-wrap-layer.la

# ------------------------------------------------------------------------------
# The code

libgkm_wrap_layer_la_SOURCES = \
	pkcs11/wrap-layer/gkm-wrap-layer.c \
	pkcs11/wrap-layer/gkm-wrap-layer.h \
	pkcs11/wrap-layer/gkm-wrap-login.c \
	pkcs11/wrap-layer/gkm-wrap-login.h \
	pkcs11/wrap-layer/gkm-wrap-prompt.c \
	pkcs11/wrap-layer/gkm-wrap-prompt.h
libgkm_wrap_layer_la_LIBADD = \
	libgkm.la \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(GIO_LIBS)
libgkm_wrap_layer_la_CFLAGS = \
	$(GCR_BASE_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GIO_CFLAGS)

# ------------------------------------------------------------------------------
# TESTS

wrap_layer_CFLAGS = \
	$(GCR_BASE_CFLAGS)

wrap_layer_LIBS = \
	libgkm-wrap-layer.la \
	libgkm-mock-secret-store.a \
	libgkm.la \
	libegg.la \
	$(GCR_BASE_LIBS) \
	$(GLIB_LIBS)

wrap_layer_TESTS = \
	test-create-credential \
	test-init-pin \
	test-login-auto \
	test-login-hints \
	test-login-keyring \
	test-login-specific \
	test-login-user \
	test-set-pin

test_create_credential_SOURCES = pkcs11/wrap-layer/test-create-credential.c
test_create_credential_LDADD = $(wrap_layer_LIBS)
test_create_credential_CFLAGS = $(wrap_layer_CFLAGS)

test_init_pin_SOURCES = pkcs11/wrap-layer/test-init-pin.c
test_init_pin_LDADD = $(wrap_layer_LIBS)
test_init_pin_CFLAGS = $(wrap_layer_CFLAGS)

test_login_auto_SOURCES = pkcs11/wrap-layer/test-login-auto.c
test_login_auto_LDADD = $(wrap_layer_LIBS)
test_login_auto_CFLAGS = $(wrap_layer_CFLAGS)

test_login_hints_SOURCES = pkcs11/wrap-layer/test-login-hints.c
test_login_hints_LDADD = $(wrap_layer_LIBS)

test_login_keyring_SOURCES = pkcs11/wrap-layer/test-login-keyring.c
test_login_keyring_LDADD = $(wrap_layer_LIBS)

test_login_specific_SOURCES = pkcs11/wrap-layer/test-login-specific.c
test_login_specific_LDADD = $(wrap_layer_LIBS)
test_login_specific_CFLAGS = $(wrap_layer_CFLAGS)

test_login_user_SOURCES = pkcs11/wrap-layer/test-login-user.c
test_login_user_LDADD = $(wrap_layer_LIBS)
test_login_user_CFLAGS = $(wrap_layer_CFLAGS)

test_set_pin_SOURCES = pkcs11/wrap-layer/test-set-pin.c
test_set_pin_LDADD = $(wrap_layer_LIBS)
test_set_pin_CFLAGS = $(wrap_layer_CFLAGS)

check_PROGRAMS += $(wrap_layer_TESTS)
TESTS += $(wrap_layer_TESTS)

noinst_LIBRARIES += libgkm-mock-secret-store.a

libgkm_mock_secret_store_a_SOURCES = \
	pkcs11/wrap-layer/mock-secret-store.c