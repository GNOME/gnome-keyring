
# ------------------------------------------------------------------------------
# The secret store component code

noinst_LTLIBRARIES += \
	libgkm-secret-store.la

libgkm_secret_store_la_SOURCES = \
	pkcs11/secret-store/gkm-secret-binary.c \
	pkcs11/secret-store/gkm-secret-binary.h \
	pkcs11/secret-store/gkm-secret-collection.h \
	pkcs11/secret-store/gkm-secret-collection.c \
	pkcs11/secret-store/gkm-secret-compat.h \
	pkcs11/secret-store/gkm-secret-compat.c \
	pkcs11/secret-store/gkm-secret-data.h \
	pkcs11/secret-store/gkm-secret-data.c \
	pkcs11/secret-store/gkm-secret-fields.h \
	pkcs11/secret-store/gkm-secret-fields.c \
	pkcs11/secret-store/gkm-secret-item.h \
	pkcs11/secret-store/gkm-secret-item.c \
	pkcs11/secret-store/gkm-secret-module.h \
	pkcs11/secret-store/gkm-secret-module.c \
	pkcs11/secret-store/gkm-secret-object.h \
	pkcs11/secret-store/gkm-secret-object.c \
	pkcs11/secret-store/gkm-secret-search.h \
	pkcs11/secret-store/gkm-secret-search.c \
	pkcs11/secret-store/gkm-secret-store.h \
	pkcs11/secret-store/gkm-secret-types.h \
	pkcs11/secret-store/gkm-secret-textual.c \
	pkcs11/secret-store/gkm-secret-textual.h
libgkm_secret_store_la_CFLAGS = \
	$(GOBJECT_CFLAGS) \
	$(GMODULE_CFLAGS)

# ------------------------------------------------------------------------------
# The standalone module

module_LTLIBRARIES += \
	gkm-secret-store-standalone.la

gkm_secret_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList|g_module_check_init'
gkm_secret_store_standalone_la_SOURCES = \
	pkcs11/secret-store/gkm-secret-standalone.c
gkm_secret_store_standalone_la_LIBADD = \
	libgkm-secret-store.la \
	libgkm.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(LIBGCRYPT_LIBS)

# -------------------------------------------------------------------------------
# TESTS

secret_store_LIBS = \
	libgkm-mock-secret-module.a \
	libgkm-secret-store.la \
	libgkm.la \
	libegg.la \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

noinst_LIBRARIES += libgkm-mock-secret-module.a

libgkm_mock_secret_module_a_SOURCES = \
	pkcs11/secret-store/mock-secret-module.c \
	pkcs11/secret-store/mock-secret-module.h

noinst_PROGRAMS += \
	dump-keyring0-format

dump_keyring0_format_SOURCES = \
	pkcs11/secret-store/dump-keyring0-format.c
dump_keyring0_format_LDADD = $(secret_store_LIBS)

secret_store_TESTS = \
	test-secret-compat \
	test-secret-fields \
	test-secret-data \
	test-secret-object \
	test-secret-collection \
	test-secret-item \
	test-secret-schema \
	test-secret-search \
	test-secret-textual \
	test-secret-binary

test_secret_compat_SOURCES = pkcs11/secret-store/test-secret-compat.c
test_secret_compat_LDADD = $(secret_store_LIBS)

test_secret_fields_SOURCES = pkcs11/secret-store/test-secret-fields.c
test_secret_fields_LDADD = $(secret_store_LIBS)

test_secret_data_SOURCES = pkcs11/secret-store/test-secret-data.c
test_secret_data_LDADD = $(secret_store_LIBS)

test_secret_object_SOURCES = pkcs11/secret-store/test-secret-object.c
test_secret_object_LDADD = $(secret_store_LIBS)

test_secret_collection_SOURCES = pkcs11/secret-store/test-secret-collection.c
test_secret_collection_LDADD = $(secret_store_LIBS)

test_secret_item_SOURCES = pkcs11/secret-store/test-secret-item.c
test_secret_item_LDADD = $(secret_store_LIBS)

test_secret_schema_SOURCES = pkcs11/secret-store/test-secret-schema.c
test_secret_schema_LDADD = $(secret_store_LIBS)

test_secret_search_SOURCES = pkcs11/secret-store/test-secret-search.c
test_secret_search_LDADD = $(secret_store_LIBS)

test_secret_textual_SOURCES = pkcs11/secret-store/test-secret-textual.c
test_secret_textual_LDADD = $(secret_store_LIBS)

test_secret_binary_SOURCES = pkcs11/secret-store/test-secret-binary.c
test_secret_binary_LDADD = $(secret_store_LIBS)

EXTRA_DIST += pkcs11/secret-store/fixtures

check_PROGRAMS += $(secret_store_TESTS)
TESTS += $(secret_store_TESTS)
