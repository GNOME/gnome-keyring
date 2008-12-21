
# TODO: Are we sure this is the best location for these headers? 
incdir = $(includedir)/gp11

inc_HEADERS = \
	pkcs11g.h \
	pkcs11n.h 

EXTRA_DIST = \
	pkcs11.h

# ------------------------------------------------------------------------------
# The pkcs11 module 

moduledir = $(libdir)/gnome-keyring/

MODULE_SRCS = \
	gkr-pkcs11-module.c \
	gkr-pkcs11-message.c gkr-pkcs11-message.h \
	gkr-pkcs11-mechanisms.h gkr-pkcs11-calls.h 

module_LTLIBRARIES = gnome-keyring-pkcs11.la

gnome_keyring_pkcs11_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

gnome_keyring_pkcs11_la_CFLAGS = \
	-I. \
	-I$(top_srcdir)

gnome_keyring_pkcs11_la_SOURCES = $(MODULE_SRCS)

gnome_keyring_pkcs11_la_LIBADD = \
	$(top_builddir)/common/libgkr-module-common.la 


if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . rpc gck $(TESTS_DIR)

