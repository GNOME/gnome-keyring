
# ------------------------------------------------------------------------------
# The ssh-store component code

noinst_LTLIBRARIES += \
	libgkm-ssh-store.la

libgkm_ssh_store_la_SOURCES = \
	pkcs11/ssh-store/gkm-ssh-store.h \
	pkcs11/ssh-store/gkm-ssh-module.c pkcs11/ssh-store/gkm-ssh-module.h \
	pkcs11/ssh-store/gkm-ssh-openssh.c pkcs11/ssh-store/gkm-ssh-openssh.h \
	pkcs11/ssh-store/gkm-ssh-private-key.c pkcs11/ssh-store/gkm-ssh-private-key.h \
	pkcs11/ssh-store/gkm-ssh-public-key.c pkcs11/ssh-store/gkm-ssh-public-key.h

# ------------------------------------------------------------------------------
# The standalone module

module_LTLIBRARIES += \
	gkm-ssh-store-standalone.la

gkm_ssh_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList|g_module_check_init'
gkm_ssh_store_standalone_la_SOURCES = \
	pkcs11/ssh-store/gkm-ssh-standalone.c
gkm_ssh_store_standalone_la_LIBADD = \
	libgkm-ssh-store.la \
	libgkm.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(LIBGCRYPT_LIBS)

# -------------------------------------------------------------------------------
# TESTS

ssh_store_LIBS = \
	libgkm-mock-ssh-module.a \
	libgkm-ssh-store.la \
	libgkm.la \
	libegg.la \
	$(GLIB_LIBS) \
	$(LIBGCRYPT_LIBS)

# if WITH_P11_TESTS
# CHECK_PROGS = check-ssh-module
# else
# CHECK_PROGS =
# endif
# CHECK_FILES = \
#	p11-tests.conf
# check_ssh_module_CFLAGS = $(P11_TESTS_CFLAGS)
# check_ssh_module_LDADD = $(P11_TESTS_LIBS) $(LDADD)
# p11-tests.conf.in

ssh_store_TESTS = \
	test-ssh-openssh \
	test-private-key

test_ssh_openssh_SOURCES = pkcs11/ssh-store/test-ssh-openssh.c
test_ssh_openssh_LDADD = $(ssh_store_LIBS)

test_private_key_SOURCES = pkcs11/ssh-store/test-private-key.c
test_private_key_LDADD = $(ssh_store_LIBS)

check_PROGRAMS += $(ssh_store_TESTS)
TESTS += $(ssh_store_TESTS)

noinst_LIBRARIES += libgkm-mock-ssh-module.a

libgkm_mock_ssh_module_a_SOURCES = \
	pkcs11/ssh-store/mock-ssh-module.c \
	pkcs11/ssh-store/mock-ssh-module.h

EXTRA_DIST += pkcs11/ssh-store/fixtures
