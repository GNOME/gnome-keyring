
INCLUDES = \
	-I$(top_builddir) \
    	-I$(top_srcdir) \
    	-I$(top_srcdir)/pkcs11 \
    	$(GOBJECT_CFLAGS) \
	$(LIBGCRYPT_CFLAGS) \
	$(GLIB_CFLAGS)
	
			
# ------------------------------------------------------------------------------
# The roots component code

noinst_LTLIBRARIES = \
	libgck-roots.la

libgck_roots_la_SOURCES = \
	gck-roots-module.c gck-roots-module.h \
	gck-roots-certificate.c gck-roots-certificate.h

# ------------------------------------------------------------------------------
# The standalone module 

moduledir = $(libdir)/gnome-keyring/standalone/

module_LTLIBRARIES = \
	gck-roots-module.la

gck_roots_module_la_LDFLAGS = \
	-module -avoid-version \
	-no-undefined -export-symbols-regex 'C_GetFunctionList'

gck_roots_module_la_SOURCES = \
	gck-roots-standalone.c

gck_roots_module_la_LIBADD = \
	libgck-roots.la \
	$(top_builddir)/pkcs11/gck/libgck.la \
	$(top_builddir)/common/libgkr-common-buffer.la \
	$(top_builddir)/common/libgkr-common-secure.la \
	$(GOBJECT_LIBS) \
	$(GTHREAD_LIBS) \
	$(GLIB_LIBS) \
	$(LIBTASN1_LIBS) \
	$(LIBGCRYPT_LIBS)


# -------------------------------------------------------------------------------

if WITH_TESTS
TESTS_DIR = tests
else
TESTS_DIR = 
endif

SUBDIRS = . $(TESTS_DIR)
