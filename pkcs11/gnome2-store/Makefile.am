
# ------------------------------------------------------------------------------
# The gnome2-store component code

noinst_LTLIBRARIES += \
	libgkm-gnome2-store.la

libgkm_gnome2_store_la_SOURCES = \
	pkcs11/gnome2-store/gkm-gnome2-store.h \
	pkcs11/gnome2-store/gkm-gnome2-file.c \
	pkcs11/gnome2-store/gkm-gnome2-file.h \
	pkcs11/gnome2-store/gkm-gnome2-module.c \
	pkcs11/gnome2-store/gkm-gnome2-module.h \
	pkcs11/gnome2-store/gkm-gnome2-private-key.c \
	pkcs11/gnome2-store/gkm-gnome2-private-key.h \
	pkcs11/gnome2-store/gkm-gnome2-public-key.c \
	pkcs11/gnome2-store/gkm-gnome2-public-key.h \
	pkcs11/gnome2-store/gkm-gnome2-storage.c \
	pkcs11/gnome2-store/gkm-gnome2-storage.h \
	$(NULL)

# ------------------------------------------------------------------------------
# The standalone module

module_LTLIBRARIES += \
	gkm-gnome2-store-standalone.la

gkm_gnome2_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'
gkm_gnome2_store_standalone_la_SOURCES = \
	pkcs11/gnome2-store/gkm-gnome2-standalone.c
gkm_gnome2_store_standalone_la_LIBADD = \
	libgkm-gnome2-store.la \
	libgkm.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

# -------------------------------------------------------------------------------
# TESTS

gnome2_store_LIBS = \
	libgkm-gnome2-store.la \
	libgkm.la \
	libegg.la \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

# if WITH_P11_TESTS
# CHECK_PROGS = check-gnome2-module
# CHECK_FILES = \
# 	p11-tests.conf
# check_gnome2_module_CFLAGS = $(P11_TESTS_CFLAGS)
# check_gnome2_module_LDADD = $(P11_TESTS_LIBS) $(LDADD)
# endif

gnome2_store_TESTS = \
	test-gnome2-file \
	test-gnome2-storage \
	test-gnome2-private-key \
	test-import

test_gnome2_file_SOURCES = pkcs11/gnome2-store/test-gnome2-file.c
test_gnome2_file_LDADD = $(gnome2_store_LIBS)

test_gnome2_storage_SOURCES = \
	pkcs11/gnome2-store/test-gnome2-storage.c \
	pkcs11/gnome2-store/mock-gnome2-module.c \
	pkcs11/gnome2-store/mock-gnome2-module.h
test_gnome2_storage_LDADD = $(gnome2_store_LIBS)

test_gnome2_private_key_SOURCES = \
	pkcs11/gnome2-store/test-gnome2-private-key.c \
	pkcs11/gnome2-store/mock-gnome2-module.c \
	pkcs11/gnome2-store/mock-gnome2-module.h
test_gnome2_private_key_LDADD = $(gnome2_store_LIBS)

test_import_SOURCES = pkcs11/gnome2-store/test-import.c
test_import_CFLAGS = $(GCR_BASE_CFLAGS) $(GCK_CFLAGS)
test_import_LDADD = $(GCR_BASE_LIBS) $(GCK_LIBS) $(gnome2_store_LIBS)

check_PROGRAMS += $(gnome2_store_TESTS)
TESTS += $(gnome2_store_TESTS)

noinst_PROGRAMS += \
	frob-gnome2-file

frob_gnome2_file_SOURCES = pkcs11/gnome2-store/frob-gnome2-file.c
frob_gnome2_file_LDADD = $(gnome2_store_LIBS)

EXTRA_DIST += \
	pkcs11/gnome2-store/p11-tests.conf.in \
	pkcs11/gnome2-store/fixtures
