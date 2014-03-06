
noinst_LTLIBRARIES += \
	libgkm-rpc-layer.la

noinst_PROGRAMS += \
	gkm-rpc-daemon-standalone

# ------------------------------------------------------------------------------
# The dispatch code

libgkm_rpc_layer_la_SOURCES = \
	pkcs11/rpc-layer/gkm-rpc-dispatch.c \
	pkcs11/rpc-layer/gkm-rpc-layer.h \
	pkcs11/rpc-layer/gkm-rpc-message.c \
	pkcs11/rpc-layer/gkm-rpc-private.h \
	pkcs11/rpc-layer/gkm-rpc-util.c
libgkm_rpc_layer_la_LIBADD = \
	libegg-buffer.la \
	libegg-creds.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS)
libgkm_rpc_layer_la_CFLAGS = \
	$(GOBJECT_CFLAGS) \
	$(GTHREAD_CFLAGS) \
	$(GLIB_CFLAGS)

# ------------------------------------------------------------------------------
# The module code, built as the public gnome-keyring module

# This is the location that some older software looks for modules
pkcs11moduledir = $(P11_MODULE_PATH)
pkcs11module_LTLIBRARIES = \
	gnome-keyring-pkcs11.la

gnome_keyring_pkcs11_la_SOURCES = \
	pkcs11/rpc-layer/gkm-rpc-private.h \
	pkcs11/rpc-layer/gkm-rpc-module.c \
	pkcs11/rpc-layer/gkm-rpc-message.c \
	pkcs11/rpc-layer/gkm-rpc-util.c
gnome_keyring_pkcs11_la_LIBADD = \
	libegg-buffer.la \
	libegg-creds.la
gnome_keyring_pkcs11_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

# This is the configuration file that p11-kit uses to load the module
pkcs11configdir = $(P11_SYSTEM_CONFIG_MODULES)
pkcs11config_DATA = \
	pkcs11/rpc-layer/gnome-keyring.module

# -----------------------------------------------------------------------------
# The tests

gkm_rpc_daemon_standalone_SOURCES = \
	pkcs11/rpc-layer/gkm-rpc-daemon-standalone.c
gkm_rpc_daemon_standalone_LDADD = \
	$(DL_LIBS) \
	libgkm-rpc-layer.la \
	$(GLIB_LIBS)
gkm_rpc_daemon_standalone_CFLAGS = \
	$(GLIB_CFLAGS)

rpc_layer_CFLAGS = \
	$(GCK_CFLAGS)

rpc_layer_LIBS = \
	libegg-test.la \
	$(GCK_LIBS) \
	$(GIO_LIBS) \
	$(GLIB_LIBS)

rpc_layer_TESTS = \
	test-initialize

test_initialize_SOURCES = pkcs11/rpc-layer/test-initialize.c
test_initialize_LDADD = $(daemon_LIBS)
test_initialize_CFLAGS = $(daemon_CFLAGS)

check_PROGRAMS += $(rpc_layer_TESTS)
TESTS += $(rpc_layer_TESTS)
