include $(top_srcdir)/Makefile.decl

INCLUDES = \
	-I$(top_builddir) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/pkcs11 \
	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS) \
	$(GMODULE_CFLAGS)

# ------------------------------------------------------------------------------
# The xdg-store component code

noinst_LTLIBRARIES = \
	libgkm-xdg-store.la

libgkm_xdg_store_la_SOURCES = \
	gkm-xdg-store.h \
	gkm-xdg-asn1-defs.c gkm-xdg-asn1-defs.h \
	gkm-xdg-assertion.c gkm-xdg-assertion.h \
	gkm-xdg-module.c gkm-xdg-module.h \
	gkm-xdg-trust.c gkm-xdg-trust.h \
	xdg.asn.h \
	$(NULL)

EXTRA_DIST = \
	xdg.asn \
	$(NULL)

# ------------------------------------------------------------------------------
# The standalone module

moduledir = $(pkcs11standalonedir)

module_LTLIBRARIES = \
	gkm-xdg-store-standalone.la

gkm_xdg_store_standalone_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList|g_module_check_init'

gkm_xdg_store_standalone_la_SOURCES = \
	gkm-xdg-standalone.c

gkm_xdg_store_standalone_la_LIBADD = \
	libgkm-xdg-store.la \
	$(top_builddir)/pkcs11/gkm/libgkm.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(GMODULE_LIBS) \
	$(LIBGCRYPT_LIBS)


# -------------------------------------------------------------------------------

SUBDIRS = . tests

asn:
	asn1Parser -o xdg.asn.h xdg.asn
	sed -i 's|#include.*|/* \0 */|' xdg.asn.h
