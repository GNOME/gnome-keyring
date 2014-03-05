
# ------------------------------------------------------------------------------
# The xdg-store component code

noinst_LTLIBRARIES += \
	libgkm-xdg-store.la

libgkm_xdg_store_la_SOURCES = \
	pkcs11/xdg-store/gkm-xdg-store.h \
	pkcs11/xdg-store/gkm-xdg-asn1-defs.c \
	pkcs11/xdg-store/gkm-xdg-asn1-defs.h \
	pkcs11/xdg-store/gkm-xdg-assertion.c \
	pkcs11/xdg-store/gkm-xdg-assertion.h \
	pkcs11/xdg-store/gkm-xdg-module.c \
	pkcs11/xdg-store/gkm-xdg-module.h \
	pkcs11/xdg-store/gkm-xdg-trust.c \
	pkcs11/xdg-store/gkm-xdg-trust.h \
	pkcs11/xdg-store/xdg.asn.h \
	$(NULL)

ASN1_FILES += \
	pkcs11/xdg-store/xdg.asn \
	$(NULL)

# ------------------------------------------------------------------------------
# The standalone module

module_LTLIBRARIES += \
	gkm-xdg-store-standalone.la

gkm_xdg_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList|g_module_check_init'
gkm_xdg_store_standalone_la_SOURCES = \
	pkcs11/xdg-store/gkm-xdg-standalone.c
gkm_xdg_store_standalone_la_LIBADD = \
	libgkm-xdg-store.la \
	libgkm.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(LIBGCRYPT_LIBS)

# -------------------------------------------------------------------------------
# TESTS

xdg_store_LIBS = \
	libgkm-mock-xdg-module.a \
	libgkm-xdg-store.la \
	libgkm.la \
	libegg.la \
	$(GLIB_LIBS) \
	$(GTHREAD_LIBS) \
	$(LIBGCRYPT_LIBS)

# if WITH_P11_TESTS
# CHECK_PROGS = check-xdg-module
# else
# CHECK_PROGS =
# endif
# check_xdg_module_CFLAGS = $(P11_TESTS_CFLAGS)
# check_xdg_module_LDADD = $(P11_TESTS_LIBS) $(LDADD)

xdg_store_TESTS = \
	test-xdg-module \
	test-xdg-trust

test_xdg_module_SOURCES = pkcs11/xdg-store/test-xdg-module.c
test_xdg_module_LDADD = $(xdg_store_LIBS)

test_xdg_trust_SOURCES = pkcs11/xdg-store/test-xdg-trust.c
test_xdg_trust_LDADD = $(xdg_store_LIBS)

check_PROGRAMS += $(xdg_store_TESTS)
TESTS += $(xdg_store_TESTS)

EXTRA_DIST += pkcs11/xdg-store/fixtures

noinst_PROGRAMS += \
	frob-trust-file \
	dump-trust-file

frob_trust_file_SOURCES = pkcs11/xdg-store/frob-trust-file.c
frob_trust_file_LDADD = $(xdg_store_LIBS)

dump_trust_file_SOURCES = pkcs11/xdg-store/dump-trust-file.c
dump_trust_file_LDADD = $(xdg_store_LIBS)

noinst_LIBRARIES += libgkm-mock-xdg-module.a

libgkm_mock_xdg_module_a_SOURCES = \
	pkcs11/xdg-store/mock-xdg-module.c \
	pkcs11/xdg-store/mock-xdg-module.h
